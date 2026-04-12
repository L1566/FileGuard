package handler

import (
	"encoding/json"
	"net/http"

	httputil "github.com/L1566/FileGuard/pkg/http"
	"github.com/L1566/FileGuard/pkg/logger"
)

func AgentEventHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid json")
		return
	}
	logger.Debugf("Agent event: %v", payload)
	// 这里可以将事件存入审计日志或数据库
	httputil.Success(w, map[string]string{"status": "received"})
}

func AgentHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]string
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid json")
		return
	}
	logger.Debugf("Agent heartbeat from %s", payload["client_id"])
	httputil.Success(w, map[string]string{"status": "ok"})
}
