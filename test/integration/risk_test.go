package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/L1566/FileGuard/internal/riskservice/handler"
	"github.com/L1566/FileGuard/pkg/risk"
)

func TestRiskServiceEvaluate(t *testing.T) {
	scorer, err := risk.NewScorer(risk.ScorerConfig{
		Model:     "claude-sonnet-4-6",
		APIKeyEnv: "FILEGUARD_LLM_API_KEY",
		Timeout:   10000,
		CacheSize: 100,
		CacheTTL:  300,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := handler.NewHandler(scorer)
	body := `{
		"request_id": "test-001",
		"subject": {"role": "engineer", "project": "ev_battery"},
		"resource": {"path": "/battery/test.xlsx", "sensitivity": "internal"},
		"environment": {"time": "2026-06-23T14:00:00+08:00", "ip": "10.0.0.1"},
		"context": {
			"recent_access_count_1h": 3,
			"unique_files_accessed_1h": 2,
			"is_work_hours": true,
			"is_known_location": true,
			"content_summary": "test battery parameters"
		}
	}`
	req := httptest.NewRequest("POST", "/api/risk/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Evaluate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp risk.EvaluateResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.RiskScore < 0 || resp.RiskScore > 1.0 {
		t.Errorf("risk_score out of range: %f", resp.RiskScore)
	}
	if resp.RiskLevel == "" {
		t.Error("risk_level should not be empty")
	}
	if resp.RequestID != "test-001" {
		t.Errorf("request_id = %s, want test-001", resp.RequestID)
	}
	t.Logf("Risk score: %.2f, level: %s, recommendation: %s",
		resp.RiskScore, resp.RiskLevel, resp.Recommendation)
}

func TestRiskServiceHealthCheck(t *testing.T) {
	scorer, _ := risk.NewScorer(risk.ScorerConfig{
		Model: "test", APIKeyEnv: "NONE",
		Timeout: 10000, CacheSize: 10, CacheTTL: 300,
	})
	h := handler.NewHandler(scorer)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	h.HealthCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("health check returned %d", rec.Code)
	}
}

func TestRiskServiceEmptyAPIKey(t *testing.T) {
	scorer, _ := risk.NewScorer(risk.ScorerConfig{
		Model: "claude-sonnet-4-6", APIKeyEnv: "NONEXISTENT_ENV_VAR",
		Timeout: 5000, CacheSize: 10, CacheTTL: 300,
	})

	resp, err := scorer.Evaluate(nil, &risk.EvaluateRequest{
		RequestID: "test",
		Subject:   risk.SubjectContext{Role: "guest"},
		Resource:  risk.ResourceContext{Path: "/test.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RiskScore != 0.1 || resp.Recommendation != "allow" {
		t.Errorf("expected default low-risk (0.1/allow), got score=%.2f rec=%s", resp.RiskScore, resp.Recommendation)
	}
}

var _ = io.Discard // suppress unused import warning for io
