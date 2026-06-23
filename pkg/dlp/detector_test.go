package dlp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func newTestDetector(t *testing.T, rules []Rule) *Detector {
	t.Helper()
	rs := NewRuleSet()
	for _, r := range rules {
		if err := rs.AddRule(r); err != nil {
			t.Fatalf("AddRule(%s): %v", r.ID, err)
		}
	}
	return NewDetector(rs)
}

func TestDetect_AllThreeActions(t *testing.T) {
	det := newTestDetector(t, []Rule{
		{ID: "blk", Name: "block-rule", Pattern: "TOPSECRET", IsRegex: false, Sensitivity: "critical", Action: "block", Enabled: true},
		{ID: "alt", Name: "alert-rule", Pattern: "CONFIDENTIAL", IsRegex: false, Sensitivity: "medium", Action: "alert", Enabled: true},
		{ID: "log", Name: "log-rule", Pattern: "internal-memo", IsRegex: false, Sensitivity: "low", Action: "log", Enabled: true},
	})

	content := []byte("this TOPSECRET doc is CONFIDENTIAL and an internal-memo")
	findings, err := det.Detect(context.Background(), content)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	got := map[string]string{}
	for _, f := range findings {
		got[f.Action] = f.RuleName
	}
	for _, action := range []string{"block", "alert", "log"} {
		if got[action] == "" {
			t.Errorf("missing finding for action %q", action)
		}
	}
}

func TestDetect_DisabledRuleSkipped(t *testing.T) {
	det := newTestDetector(t, []Rule{
		{ID: "off", Name: "disabled", Pattern: "secret", Action: "block", Enabled: false},
	})
	findings, _ := det.Detect(context.Background(), []byte("a secret here"))
	if len(findings) != 0 {
		t.Fatalf("disabled rule must not match, got %+v", findings)
	}
}

func TestDetect_RegexRule(t *testing.T) {
	det := newTestDetector(t, []Rule{
		{ID: "cc", Name: "credit-card", Pattern: `\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`, IsRegex: true, Action: "block", Enabled: true},
	})
	findings, _ := det.Detect(context.Background(), []byte("card 1234-5678-9012-3456"))
	if len(findings) != 1 || findings[0].Action != "block" {
		t.Fatalf("expected one block finding, got %+v", findings)
	}
}

func TestDetector_HitFiles(t *testing.T) {
	projectRoot := filepath.Join("..", "..")

	rs := NewRuleSet()
	rulesPath := filepath.Join(projectRoot, "configs", "dlp_rules.json")
	if err := rs.LoadFromFile(rulesPath); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	det := NewDetector(rs)

	tests := []struct {
		name     string
		filename string
		wantHits int
		wantIDs  []string
	}{
		{"credit_card", "credit_card.txt", 1, []string{"dlp_credit_card"}},
		{"battery_params", "battery_params.txt", 1, []string{"dlp_battery_params"}},
		{"confidential", "confidential.txt", 1, []string{"dlp_confidential"}},
		{"top_secret", "top_secret.txt", 1, []string{"dlp_top_secret"}},
		{"multi_hit", "multi_hit.txt", 4, []string{"dlp_credit_card", "dlp_battery_params", "dlp_confidential", "dlp_top_secret"}},
		{"clean", "clean.txt", 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(projectRoot, "data", "test_dlp", tt.filename)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read file %s: %v", path, err)
			}

			findings, err := det.Detect(context.Background(), data)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}

			if len(findings) != tt.wantHits {
				t.Errorf("hit count = %d, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  got: %s (%s)", f.RuleID, f.Action)
				}
			}

			if tt.wantIDs != nil {
				gotIDs := make(map[string]bool)
				for _, f := range findings {
					gotIDs[f.RuleID] = true
				}
				for _, id := range tt.wantIDs {
					if !gotIDs[id] {
						t.Errorf("missing hit for rule %s", id)
					}
				}
			}
		})
	}
}
