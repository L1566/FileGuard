package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	"github.com/L1566/FileGuard/pkg/risk"
)

// mockRiskServer 启动一个返回固定评分响应的 Risk Service。
func mockRiskServer(t *testing.T, resp risk.EvaluateResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newRiskHandler(t *testing.T, serviceURL, mode, fallback string) *FileHandler {
	t.Helper()
	auditLogger, err := audit.NewFileLogger(t.TempDir() + "/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditLogger.Close() })

	var client *risk.Client
	if serviceURL != "" {
		client = risk.NewClient(serviceURL, 2*time.Second)
	}
	h := NewFileHandler(nil, nil, auditLogger, nil, nil, client)
	h.SetRiskPolicy(mode, fallback)
	return h
}

func callEnforce(h *FileHandler) (*audit.AuditEvent, bool) {
	event := &audit.AuditEvent{Result: "success", Timestamp: time.Now()}
	rec := httptest.NewRecorder()
	blocked := h.enforceRisk(rec, context.Background(), "projects/secret.xlsx",
		abac.Subject{ID: "alice", Role: "engineer"},
		abac.Resource{Path: "projects/secret.xlsx"},
		abac.Environment{Time: time.Now().Format(time.RFC3339), IP: "10.0.0.1"},
		event)
	return event, blocked
}

func TestEnforceRisk_ShadowNeverBlocks(t *testing.T) {
	srv := mockRiskServer(t, risk.EvaluateResponse{RiskScore: 0.95, RiskLevel: "critical", Recommendation: "deny"})
	h := newRiskHandler(t, srv.URL, "shadow", "allow")

	event, blocked := callEnforce(h)
	if blocked {
		t.Fatal("shadow mode must never block, even for critical score")
	}
	if event.Details["risk_score"] != 0.95 {
		t.Errorf("shadow mode must still record risk_score, got %v", event.Details["risk_score"])
	}
	if event.Details["risk_mode"] != "shadow" {
		t.Errorf("risk_mode = %v, want shadow", event.Details["risk_mode"])
	}
}

func TestEnforceRisk_MonitorPreservesABAC(t *testing.T) {
	srv := mockRiskServer(t, risk.EvaluateResponse{RiskScore: 0.95, RiskLevel: "critical", Recommendation: "deny"})
	h := newRiskHandler(t, srv.URL, "monitor", "allow")

	event, blocked := callEnforce(h)
	if blocked {
		t.Fatal("monitor mode must preserve ABAC decision (no hard deny)")
	}
	if event.Details["risk_would_deny"] != true {
		t.Errorf("monitor mode should flag risk_would_deny, got %v", event.Details["risk_would_deny"])
	}
}

func TestEnforceRisk_ActiveDenies(t *testing.T) {
	srv := mockRiskServer(t, risk.EvaluateResponse{RiskScore: 0.95, RiskLevel: "critical", Recommendation: "deny"})
	h := newRiskHandler(t, srv.URL, "active", "allow")

	event, blocked := callEnforce(h)
	if !blocked {
		t.Fatal("active mode must block on deny action")
	}
	if event.Result != "failure" {
		t.Errorf("event.Result = %q, want failure", event.Result)
	}
	if event.Details["risk_enforced"] != "deny" {
		t.Errorf("risk_enforced = %v, want deny", event.Details["risk_enforced"])
	}
}

func TestEnforceRisk_ActiveAllowsLowScore(t *testing.T) {
	srv := mockRiskServer(t, risk.EvaluateResponse{RiskScore: 0.1, RiskLevel: "low", Recommendation: "allow"})
	h := newRiskHandler(t, srv.URL, "active", "allow")

	_, blocked := callEnforce(h)
	if blocked {
		t.Fatal("active mode must allow low score")
	}
}

func TestEnforceRisk_FallbackAllow(t *testing.T) {
	// 无服务可用 URL，触发降级
	h := newRiskHandler(t, "http://127.0.0.1:1", "active", "allow")

	event, blocked := callEnforce(h)
	if blocked {
		t.Fatal("fallback=allow must not block when risk service is unavailable")
	}
	if event.Details["risk_degraded"] != true {
		t.Errorf("expected risk_degraded=true, got %v", event.Details["risk_degraded"])
	}
}

func TestEnforceRisk_FallbackDeny(t *testing.T) {
	h := newRiskHandler(t, "http://127.0.0.1:1", "active", "deny")

	event, blocked := callEnforce(h)
	if !blocked {
		t.Fatal("fallback=deny must block when risk service is unavailable")
	}
	if event.Result != "failure" {
		t.Errorf("event.Result = %q, want failure", event.Result)
	}
}

func TestEnforceRisk_DisabledNoClient(t *testing.T) {
	h := newRiskHandler(t, "", "active", "deny")
	_, blocked := callEnforce(h)
	if blocked {
		t.Fatal("no risk client => never blocks")
	}
}

func TestSetRiskPolicy_DefaultsAndOverride(t *testing.T) {
	h := NewFileHandler(nil, nil, nil, nil, nil, nil)
	if h.riskMode != "shadow" || h.riskFallback != "allow" {
		t.Fatalf("defaults wrong: mode=%s fallback=%s", h.riskMode, h.riskFallback)
	}
	// 空字符串保留默认
	h.SetRiskPolicy("", "")
	if h.riskMode != "shadow" || h.riskFallback != "allow" {
		t.Fatalf("empty args must preserve defaults: mode=%s fallback=%s", h.riskMode, h.riskFallback)
	}
	h.SetRiskPolicy("active", "deny")
	if h.riskMode != "active" || h.riskFallback != "deny" {
		t.Fatalf("override failed: mode=%s fallback=%s", h.riskMode, h.riskFallback)
	}
}
