package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	httputil "github.com/L1566/FileGuard/pkg/http"
	"github.com/L1566/FileGuard/pkg/logger"
)

// AgentHandler 处理终端代理上报的事件和心跳
type AgentHandler struct {
	audit audit.Logger
}

// NewAgentHandler 创建 Agent 事件处理器
func NewAgentHandler(audit audit.Logger) *AgentHandler {
	return &AgentHandler{audit: audit}
}

// Event 处理文件事件上报
func (h *AgentHandler) Event(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid json")
		return
	}

	// 写入审计日志
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), audit.AuditEvent{
			ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
			EventType: audit.EventAccess,
			Subject:   abac.Subject{Type: "agent"},
			Resource:  abac.Resource{Path: fmt.Sprintf("%v", payload["path"])},
			Result:    "received",
			Details:   map[string]interface{}{"payload": payload},
		})
	}

	logger.Debugf("Agent event: %v", payload)
	httputil.Success(w, map[string]string{"status": "received"})
}

// Heartbeat 处理心跳上报
func (h *AgentHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	var payload map[string]string
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid json")
		return
	}

	clientID := payload["client_id"]

	// 写入审计日志
	if h.audit != nil {
		_ = h.audit.Log(r.Context(), audit.AuditEvent{
			ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
			Timestamp: time.Now(),
			EventType: audit.EventAccess,
			Subject:   abac.Subject{Type: "agent", ID: clientID},
			Result:    "ok",
		})
	}

	logger.Debugf("Agent heartbeat from %s", clientID)
	httputil.Success(w, map[string]string{"status": "ok"})
}
