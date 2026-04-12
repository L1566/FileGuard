package handler

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/L1566/FileGuard/internal/gateway/middleware"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/storage"
	"github.com/gorilla/mux"

	httputil "github.com/L1566/FileGuard/pkg/http"
)

type FileHandler struct {
	storage   storage.Storage
	evaluator abac.Evaluator
	audit     audit.Logger
}

func NewFileHandler(storage storage.Storage, evaluator abac.Evaluator, audit audit.Logger) *FileHandler {
	return &FileHandler{
		storage:   storage,
		evaluator: evaluator,
		audit:     audit,
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
		Sensitivity: "internal", // 可从文件元数据读取，简化
	}

	// 策略评估
	decision, err := h.evaluator.Evaluate(r.Context(), subject, resource, env)
	if err != nil {
		logger.Errorf("Policy evaluation error: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	// 记录审计
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

	// 允许访问，读取文件
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

	// 记录成功审计
	_ = h.audit.Log(r.Context(), event)

	// 返回文件内容
	w.Header().Set("Content-Type", detectContentType(filePath))
	w.Header().Set("X-FileGuard-Allowed", "true")
	io.Copy(w, reader)
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

	// 对于上传，可以定义写权限，这里简化复用评估（需策略支持写操作）
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

	// 保存文件
	err = h.storage.Put(r.Context(), filePath, r.Body, nil)
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
	default:
		return "application/octet-stream"
	}
}
