package handler

import (
	"bytes"
	"context"
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
	"github.com/L1566/FileGuard/pkg/risk"
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
	riskClient  *risk.Client

	// riskMode 渐进上线模式：shadow | monitor | active
	riskMode string
	// riskFallback 风险服务不可用时的降级策略：allow | deny | abac_only
	riskFallback string
}

// NewFileHandler 修改构造函数，增加 kmsClient 参数
func NewFileHandler(storage storage.Storage, evaluator abac.Evaluator, audit audit.Logger, kmsClient *kms.Client, dlpDetector *dlp.Detector, riskClient *risk.Client) *FileHandler {
	return &FileHandler{
		storage:     storage,
		evaluator:   evaluator,
		audit:       audit,
		kmsClient:   kmsClient,
		dlpDetector: dlpDetector,
		riskClient:  riskClient,
		// 安全默认：未显式配置时使用影子模式 + 允许降级
		riskMode:     "shadow",
		riskFallback: "allow",
	}
}

// SetRiskPolicy 配置 AI 风险评分的渐进上线模式与降级策略。
// mode: shadow | monitor | active；fallback: allow | deny | abac_only。
// 传入空字符串时保留安全默认值（shadow / allow）。
func (h *FileHandler) SetRiskPolicy(mode, fallback string) {
	if mode != "" {
		h.riskMode = mode
	}
	if fallback != "" {
		h.riskFallback = fallback
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

	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	subject := abac.Subject{
		ID:      claims.UserID,
		Type:    "user",
		Role:    claims.Role,
		Project: claims.Project,
	}

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

	// 风险评分（ABAC 通过后）—— 按渐进上线模式与降级策略执行
	if h.enforceRisk(w, r.Context(), filePath, subject, resource, env, &event) {
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
	needsDecrypt := keyID != "" && h.kmsClient != nil

	// 确定用于 DLP 检测的内容：密文或明文
	contentForDLP := []byte(ciphertext)

	if !needsDecrypt {
		// 兼容未加密文件或 KMS 不可用，直接返回原始内容
		if h.kmsClient == nil && keyID != "" {
			logger.Debugf("KMS unavailable, returning raw content for %s", filePath)
		}
		// DLP 检测（在提前返回之前执行，确保未加密文件也受 DLP 保护）
		if h.dlpDetector != nil {
			findings, derr := h.dlpDetector.Detect(r.Context(), contentForDLP)
			if derr == nil {
				for _, f := range findings {
					if f.Action == "block" {
						event.Result = "failure"
						mergeDetails(&event, map[string]interface{}{"dlp_action": "block", "dlp_rule": f.RuleName, "dlp": f})
						_ = h.audit.Log(r.Context(), event)
						httputil.Error(w, http.StatusForbidden, fmt.Sprintf("DLP blocked download: %s", f.RuleName))
						return
					}
				}
			}
		}
		output := []byte(ciphertext)
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

	// 在 GetFile 中，获得 plaintext 后执行 DLP 检测
	if h.dlpDetector != nil {
		findings, derr := h.dlpDetector.Detect(r.Context(), plaintext)
		if derr == nil {
			for _, f := range findings {
				switch f.Action {
				case "block":
					// 下载拦截：命中 block 规则直接拒绝
					event.Result = "failure"
					mergeDetails(&event, map[string]interface{}{
						"dlp_action": "block",
						"dlp_rule":   f.RuleName,
						"dlp":        f,
					})
					_ = h.audit.Log(r.Context(), event)
					httputil.Error(w, http.StatusForbidden, fmt.Sprintf("DLP blocked download: %s", f.RuleName))
					return
				case "alert":
					logger.Warnf("DLP alert on download: %s matched by %s", filePath, f.RuleName)
					mergeDetails(&event, map[string]interface{}{"dlp_action": "alert", "dlp_rule": f.RuleName, "dlp": f})
				case "log":
					logger.Infof("DLP log on download: %s matched by %s", filePath, f.RuleName)
					mergeDetails(&event, map[string]interface{}{"dlp_action": "log", "dlp_rule": f.RuleName, "dlp": f})
				}
				// 下载强制水印：命中敏感内容时强制加水印（即使原策略未要求）
				if f.Sensitivity == "critical" && f.Action != "block" {
					decision.Restrictions = append(decision.Restrictions, "watermark")
					logger.Infof("DLP forced watermark on %s due to rule %s", filePath, f.RuleName)
				}
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

	claims := middleware.GetClaims(r.Context())
	if claims == nil {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	subject := abac.Subject{
		ID:      claims.UserID,
		Type:    "user",
		Role:    claims.Role,
		Project: claims.Project,
	}

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

	// 风险评分（ABAC 通过后）—— 按渐进上线模式与降级策略执行
	if h.enforceRisk(w, r.Context(), filePath, subject, resource, env, &event) {
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
				switch f.Action {
				case "block":
					// 拦截上传并记录审计
					event.Result = "failure"
					mergeDetails(&event, map[string]interface{}{
						"dlp_action": "block",
						"dlp_rule":   f.RuleName,
						"dlp":        f,
					})
					_ = h.audit.Log(r.Context(), event)
					httputil.Error(w, http.StatusForbidden, fmt.Sprintf("DLP blocked: %s", f.RuleName))
					return
				case "alert":
					logger.Warnf("DLP alert: %s matched by %s", filePath, f.RuleName)
					mergeDetails(&event, map[string]interface{}{
						"dlp_action": "alert",
						"dlp_rule":   f.RuleName,
						"dlp":        f,
					})
				case "log":
					// 仅记录，不告警、不拦截
					logger.Infof("DLP log: %s matched by %s (sensitivity=%s)", filePath, f.RuleName, f.Sensitivity)
					mergeDetails(&event, map[string]interface{}{
						"dlp_action": "log",
						"dlp_rule":   f.RuleName,
						"dlp":        f,
					})
				default:
					logger.Warnf("DLP rule %s has unknown action %q, treating as log", f.RuleName, f.Action)
					mergeDetails(&event, map[string]interface{}{
						"dlp_action": "log",
						"dlp_rule":   f.RuleName,
						"dlp":        f,
					})
				}
			}
		}
	}

	// 加密并存储（KMS 不可用时直存明文）
	var fileContent []byte
	var metadata map[string]string

	if h.kmsClient != nil {
		ciphertext, keyID, err := h.kmsClient.Encrypt(r.Context(), plaintext)
		if err != nil {
			logger.Errorf("Encryption failed: %+v", err)
			httputil.Error(w, http.StatusInternalServerError, "failed to encrypt file")
			event.Result = "failure"
			event.Details = map[string]interface{}{"error": "encryption error"}
			_ = h.audit.Log(r.Context(), event)
			return
		}
		fileContent = []byte(ciphertext)
		metadata = map[string]string{
			"encrypted": "true",
			"key_id":    keyID,
		}
	} else {
		// KMS 不可用，明文存储
		fileContent = plaintext
		metadata = nil
	}

	err = h.storage.Put(r.Context(), filePath, bytes.NewReader(fileContent), metadata)
	if err != nil {
		logger.Errorf("Storage put error: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "failed to save file")
		event.Result = "failure"
		event.Details = map[string]interface{}{"error": err.Error()}
		_ = h.audit.Log(r.Context(), event)
		return
	}

	_ = h.audit.Log(r.Context(), event)
	httputil.Success(w, map[string]string{"message": "uploaded"})
}

func (h *FileHandler) evaluateRisk(ctx context.Context, subject abac.Subject, resource abac.Resource, env abac.Environment) (*risk.EvaluateResponse, error) {
	if h.riskClient == nil {
		return nil, nil
	}

	req := &risk.EvaluateRequest{
		RequestID: fmt.Sprintf("%d", time.Now().UnixNano()),
		Subject: risk.SubjectContext{
			ID:      subject.ID,
			Role:    subject.Role,
			Project: subject.Project,
		},
		Resource: risk.ResourceContext{
			Path:        resource.Path,
			Sensitivity: resource.Sensitivity,
		},
		Environment: risk.EnvironmentContext{
			Time: env.Time,
			IP:   env.IP,
		},
		Context: risk.RiskContext{
			IsWorkHours:     isWorkHours(),
			IsKnownLocation: false,
		},
	}

	resp, err := h.riskClient.Evaluate(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// enforceRisk 在 ABAC 通过后执行 AI 风险评分，并按渐进上线模式（shadow/monitor/active）
// 与降级策略（allow/deny/abac_only）作出决策。
// 返回 true 表示请求已被拒绝（响应已写入 w），调用方应立即返回。
// 无论是否拦截，风险评分结果都会写入 event.Details 供审计记录完整决策链。
func (h *FileHandler) enforceRisk(w http.ResponseWriter, ctx context.Context, filePath string, subject abac.Subject, resource abac.Resource, env abac.Environment, event *audit.AuditEvent) bool {
	if h.riskClient == nil {
		return false
	}

	riskResp, err := h.evaluateRisk(ctx, subject, resource, env)
	if err != nil || riskResp == nil {
		// 风险服务不可用，按降级策略处理
		logger.Warnf("Risk evaluation unavailable for %s: %v (fallback=%s)", filePath, err, h.riskFallback)
		mergeDetails(event, map[string]interface{}{
			"risk_mode":     h.riskMode,
			"risk_degraded": true,
			"risk_fallback": h.riskFallback,
		})
		switch h.riskFallback {
		case "deny":
			event.Result = "failure"
			_ = h.audit.Log(ctx, *event)
			httputil.Error(w, http.StatusForbidden, "risk service unavailable, denied by fallback policy")
			return true
		default:
			// allow / abac_only：保留 ABAC 决策，放行
			return false
		}
	}

	action := riskResp.RiskAction()

	// 记录完整风险信息到审计（所有模式都记录）
	mergeDetails(event, map[string]interface{}{
		"risk_score":          riskResp.RiskScore,
		"risk_level":          riskResp.RiskLevel,
		"risk_recommendation": riskResp.Recommendation,
		"risk_action":         action,
		"risk_mode":           h.riskMode,
	})

	switch h.riskMode {
	case "shadow":
		// 影子模式：仅记录，不影响决策
		logger.Infof("[risk:shadow] %s would_action=%s score=%.2f (not enforced)", filePath, action, riskResp.RiskScore)
		return false

	case "monitor":
		// 监控模式：低风险场景使用 AI 评分（step-up），高风险保留 ABAC（不硬拒绝）
		switch action {
		case "mfa":
			logger.Infof("[risk:monitor] Step-up MFA recommended for %s: score=%.2f", filePath, riskResp.RiskScore)
		case "approval":
			logger.Infof("[risk:monitor] Approval recommended for %s: score=%.2f", filePath, riskResp.RiskScore)
		case "deny":
			// 高风险保留 ABAC 决策，仅记录不拦截
			logger.Warnf("[risk:monitor] High risk for %s (score=%.2f) would deny, but ABAC decision preserved", filePath, riskResp.RiskScore)
			mergeDetails(event, map[string]interface{}{"risk_would_deny": true})
		}
		return false

	default: // active
		// 全量模式：完整执行 AI + ABAC 混合决策
		switch action {
		case "deny":
			event.Result = "failure"
			mergeDetails(event, map[string]interface{}{"risk_enforced": "deny"})
			_ = h.audit.Log(ctx, *event)
			httputil.Error(w, http.StatusForbidden, "risk score too high: "+riskResp.Reason)
			return true
		case "mfa":
			logger.Infof("[risk:active] Step-up MFA required for %s: score=%.2f", filePath, riskResp.RiskScore)
		case "approval":
			logger.Infof("[risk:active] Supervisor approval required for %s: score=%.2f", filePath, riskResp.RiskScore)
		}
		return false
	}
}

// mergeDetails 将键值合并到 event.Details，保留已有字段，构建完整决策链。
func mergeDetails(event *audit.AuditEvent, kv map[string]interface{}) {
	if event.Details == nil {
		event.Details = make(map[string]interface{}, len(kv))
	}
	for k, v := range kv {
		event.Details[k] = v
	}
}

func isWorkHours() bool {
	h := time.Now().Hour()
	return h >= 9 && h < 18
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
