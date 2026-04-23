package handler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/L1566/FileGuard/internal/gateway/middleware"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	"github.com/L1566/FileGuard/pkg/dlp"
	"github.com/L1566/FileGuard/pkg/kms"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/storage"
	"github.com/L1566/FileGuard/pkg/watermark"
	"github.com/gorilla/mux"

	httputil "github.com/L1566/FileGuard/pkg/http"
)

type FileHandler struct {
	storage     storage.Storage
	evaluator   abac.Evaluator
	audit       audit.Logger
	kmsClient   *kms.Client
	dlpDetector *dlp.Detector
}

// NewFileHandler 修改构造函数，增加 kmsClient 参数
func NewFileHandler(storage storage.Storage, evaluator abac.Evaluator, audit audit.Logger, kmsClient *kms.Client, dlpDetector *dlp.Detector) *FileHandler {
	return &FileHandler{
		storage:     storage,
		evaluator:   evaluator,
		audit:       audit,
		kmsClient:   kmsClient,
		dlpDetector: dlpDetector,
	}
}

// GetFile 处理 GET /file/{path:.*}
func (h *FileHandler) GetFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filePath := vars["path"]
	if filePath == "" {
		httputil.Error(w, http.StatusBadRequest, "missing file path")
		return
	}

	subject := middleware.GetSubject(r.Context())
	env := buildEnvironment(r)
	resource := abac.Resource{
		Type:        "file",
		Path:        filePath,
		Sensitivity: "internal",
	}

	// 策略评估
	decision, err := h.evaluator.Evaluate(r.Context(), subject, resource, env)
	if err != nil {
		logger.Errorf("Policy evaluation error: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	// 记录审计事件
	event := audit.AuditEvent{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   audit.EventAccess,
		Subject:     subject,
		Resource:    resource,
		Environment: env,
		Decision:    decision,
		Result:      "success",
	}
	if !decision.Allowed {
		event.Result = "failure"
		_ = h.audit.Log(r.Context(), event)
		httputil.Error(w, http.StatusForbidden, decision.Reason)
		return
	}

	// 从存储读取文件（此时是密文）
	reader, err := h.storage.Get(r.Context(), filePath)
	if err != nil {
		if err == storage.ErrNotFound {
			httputil.Error(w, http.StatusNotFound, "file not found")
		} else {
			logger.Errorf("Storage get error: %v", err)
			httputil.Error(w, http.StatusInternalServerError, "failed to read file")
		}
		event.Result = "failure"
		event.Details = map[string]interface{}{"error": err.Error()}
		_ = h.audit.Log(r.Context(), event)
		return
	}
	defer reader.Close()

	// 获取文件元信息（包含 key_id）
	info, err := h.storage.Stat(r.Context(), filePath)
	if err != nil {
		logger.Errorf("Failed to stat file: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to read file metadata")
		return
	}

	// 读取密文内容
	ciphertextBytes, err := io.ReadAll(reader)
	if err != nil {
		logger.Errorf("Failed to read ciphertext: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to read file")
		return
	}
	ciphertext := string(ciphertextBytes)

	// 获取密钥ID（从元数据中）
	keyID := info.Metadata["key_id"]
	if keyID == "" {
		// 兼容未加密的旧文件，直接返回原始内容
		logger.Warnf("File %s is not encrypted, returning raw content", filePath)
		output := []byte(ciphertext)
		// 仍然应用水印
		if shouldAddWatermark(decision, resource) {
			output = applyWatermark(output, subject.ID, filePath)
		}
		w.Header().Set("Content-Type", detectContentType(filePath))
		w.Write(output)
		_ = h.audit.Log(r.Context(), event)
		return
	}

	// 调用 KMS 解密
	plaintext, err := h.kmsClient.Decrypt(r.Context(), ciphertext, keyID)
	if err != nil {
		logger.Errorf("Decryption failed: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to decrypt file")
		event.Result = "failure"
		event.Details = map[string]interface{}{"error": "decryption error"}
		_ = h.audit.Log(r.Context(), event)
		return
	}

	// 在 GetFile 中，获得 plaintext 后
	if h.dlpDetector != nil {
		findings, err := h.dlpDetector.Detect(r.Context(), plaintext)
		if err == nil {
			for _, f := range findings {
				if f.Sensitivity == "critical" && f.Action != "block" {
					// 强制添加水印（即使原策略未要求）
					decision.Restrictions = append(decision.Restrictions, "watermark")
					logger.Infof("DLP forced watermark on %s due to rule %s", filePath, f.RuleName)
				}
				// 记录 DLP 命中到审计
			}
		}
	}

	// 应用水印（如果策略要求）
	output := plaintext
	if shouldAddWatermark(decision, resource) {
		output = applyWatermark(plaintext, subject.ID, filePath)
	}

	// 返回明文
	w.Header().Set("Content-Type", detectContentType(filePath))
	w.Header().Set("X-FileGuard-Allowed", "true")
	w.Write(output)

	// 记录成功审计
	_ = h.audit.Log(r.Context(), event)
}

// PutFile 处理 PUT /file/{path:.*} (上传)
func (h *FileHandler) PutFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filePath := vars["path"]
	if filePath == "" {
		httputil.Error(w, http.StatusBadRequest, "missing file path")
		return
	}

	subject := middleware.GetSubject(r.Context())
	env := buildEnvironment(r)
	resource := abac.Resource{
		Type: "file",
		Path: filePath,
	}

	// 策略评估（通常需要写权限，这里简化）
	decision, err := h.evaluator.Evaluate(r.Context(), subject, resource, env)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}
	event := audit.AuditEvent{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   audit.EventUpload,
		Subject:     subject,
		Resource:    resource,
		Environment: env,
		Decision:    decision,
		Result:      "success",
	}
	if !decision.Allowed {
		event.Result = "failure"
		_ = h.audit.Log(r.Context(), event)
		httputil.Error(w, http.StatusForbidden, decision.Reason)
		return
	}

	// 读取请求体（原始明文）
	plaintext, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("Failed to read request body: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to read file content")
		return
	}

	// 在 PutFile 中，读取请求体 plaintext 之后，加密之前
	if h.dlpDetector != nil {
		findings, err := h.dlpDetector.Detect(r.Context(), plaintext)
		if err != nil {
			logger.Errorf("DLP detection error: %v", err)
		} else {
			for _, f := range findings {
				if f.Action == "block" {
					httputil.Error(w, http.StatusForbidden, fmt.Sprintf("DLP blocked: %s", f.RuleName))
					return
				}
				if f.Action == "alert" {
					logger.Warnf("DLP alert: %s matched by %s", filePath, f.RuleName)
					// 记录到审计
					event.Details = map[string]interface{}{"dlp": f}
				}
			}
		}
	}

	// 调用 KMS 加密
	ciphertext, keyID, err := h.kmsClient.Encrypt(r.Context(), plaintext)
	if err != nil {
		logger.Errorf("Encryption failed: %+v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to encrypt file")
		event.Result = "failure"
		event.Details = map[string]interface{}{"error": "encryption error"}
		_ = h.audit.Log(r.Context(), event)
		return
	}

	// 存储密文，并保存密钥ID到元数据
	metadata := map[string]string{
		"encrypted": "true",
		"key_id":    keyID,
	}
	err = h.storage.Put(r.Context(), filePath, bytes.NewReader([]byte(ciphertext)), metadata)
	if err != nil {
		logger.Errorf("Storage put error: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to save file")
		event.Result = "failure"
		event.Details = map[string]interface{}{"error": err.Error()}
		_ = h.audit.Log(r.Context(), event)
		return
	}

	_ = h.audit.Log(r.Context(), event)
	httputil.Success(w, map[string]string{"message": "uploaded and encrypted"})
}

// 辅助函数
func buildEnvironment(r *http.Request) abac.Environment {
	return abac.Environment{
		Time: time.Now().Format(time.RFC3339),
		IP:   r.RemoteAddr,
		Attributes: map[string]interface{}{
			"user_agent": r.UserAgent(),
		},
	}
}

// detectContentType 简单检测内容类型
func detectContentType(filePath string) string {
	ext := strings.ToLower(path.Ext(filePath))
	switch ext {
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "text/yaml"
	case ".pdf":
		return "application/pdf"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	default:
		return "application/octet-stream"
	}
}

// 辅助函数：判断是否添加水印
func shouldAddWatermark(decision abac.Decision, resource abac.Resource) bool {
	// 可根据 decision.Restrictions 或文件敏感度决定
	for _, r := range decision.Restrictions {
		if r == "watermark" {
			return true
		}
	}
	// 默认对 confidential 级别文件添加水印
	return resource.Sensitivity == "confidential"
}

// 辅助函数：应用水印（统一入口）
func applyWatermark(data []byte, userID string, filePath string) []byte {
	// 判断是否为图片
	ext := strings.ToLower(filepath.Ext(filePath))
	watermarkText := fmt.Sprintf("%s @ %s", userID, time.Now().Format("2006-01-02 15:04:05"))
	if ext == ".jpg" || ext == ".jpeg" || ext == ".png" {
		reader := bytes.NewReader(data)
		watermarked, err := watermark.AddTextWatermark(reader, watermarkText, "jpeg")
		if err == nil {
			return watermarked
		}
		logger.Warnf("Image watermark failed: %v", err)
		// 降级：返回原数据
		return data
	}
	// 文本文件添加注释水印
	if ext == ".txt" || ext == ".md" || ext == ".yaml" || ext == ".json" {
		prefix := []byte(fmt.Sprintf("# Watermark: %s\n\n", watermarkText))
		return append(prefix, data...)
	}
	// 其他二进制文件简单追加水印（可能破坏格式）
	suffix := []byte(fmt.Sprintf("\n<!-- WATERMARK: %s -->", watermarkText))
	return append(data, suffix...)
}
