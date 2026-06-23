package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/risk"
	"github.com/google/uuid"
)

// Handler Risk Service HTTP 处理器
type Handler struct {
	scorer *risk.Scorer
}

func NewHandler(scorer *risk.Scorer) *Handler {
	return &Handler{scorer: scorer}
}

// Evaluate 处理风险评分请求
func (h *Handler) Evaluate(w http.ResponseWriter, r *http.Request) {
	var req risk.EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	start := time.Now()
	resp, err := h.scorer.Evaluate(r.Context(), &req)
	if err != nil {
		logger.Warnf("Risk evaluation failed: %v", err)
		resp = &risk.EvaluateResponse{
			RequestID:      req.RequestID,
			RiskScore:      0.1,
			RiskLevel:      "low",
			Recommendation: "allow",
			Reason:         "evaluation error, defaulting to allow",
		}
	}

	resp.RequestID = req.RequestID
	resp.LatencyMs = time.Since(start).Milliseconds()

	writeJSON(w, http.StatusOK, resp)
}

// HealthCheck 健康检查
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"degraded": h.scorer.IsDegraded(),
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
