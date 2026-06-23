package abac

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// MemoryEvaluator — 基础评估逻辑（已有测试的扩展）
// =============================================================================

func TestMemoryEvaluator(t *testing.T) {
	rules := []Rule{
		{
			ID:     "allow_engineer_docs",
			Effect: "allow",
			Conditions: map[string]interface{}{
				"user.role":     "engineer",
				"resource.path": "regex:^/docs/.*",
			},
		},
		{
			ID:         "deny_all",
			Effect:     "deny",
			Conditions: map[string]interface{}{},
		},
	}
	evaluator := NewMemoryEvaluator(rules)

	subject := Subject{ID: "user1", Role: "engineer"}
	resource := Resource{Path: "/docs/design.pdf"}
	env := Environment{}

	ctx := context.Background()
	decision, err := evaluator.Evaluate(ctx, subject, resource, env)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Errorf("expected allowed, got denied: %s", decision.Reason)
	}

	// 测试非匹配路径
	resource.Path = "/tmp/secret.txt"
	decision, err = evaluator.Evaluate(ctx, subject, resource, env)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Errorf("expected denied, got allowed")
	}
}

func TestRuleEvaluation(t *testing.T) {
	rule := Rule{
		Effect: "allow",
		Conditions: map[string]interface{}{
			"user.role": "admin",
			"env.ip":    []interface{}{"192.168.1.100", "10.0.0.1"},
		},
	}
	subject := Subject{Role: "admin"}
	env := Environment{IP: "10.0.0.1"}
	resource := Resource{}
	if !rule.Evaluate(subject, resource, env) {
		t.Error("rule should match")
	}

	env.IP = "8.8.8.8"
	if rule.Evaluate(subject, resource, env) {
		t.Error("rule should not match")
	}
}

// =============================================================================
// 规则匹配 — 各种条件类型
// =============================================================================

func TestRuleEvaluate_EmptyConditions(t *testing.T) {
	// 空条件意味着匹配一切
	rule := Rule{Effect: "deny", Conditions: map[string]interface{}{}}
	if !rule.Evaluate(Subject{}, Resource{}, Environment{}) {
		t.Error("rule with empty conditions should match everything")
	}
}

func TestRuleEvaluate_UserID(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"user.id": "alice"},
	}
	if !rule.Evaluate(Subject{ID: "alice"}, Resource{}, Environment{}) {
		t.Error("should match user.id")
	}
	if rule.Evaluate(Subject{ID: "bob"}, Resource{}, Environment{}) {
		t.Error("should not match wrong user.id")
	}
}

func TestRuleEvaluate_UserProject(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"user.project": "ev_project"},
	}
	if !rule.Evaluate(Subject{Project: "ev_project"}, Resource{}, Environment{}) {
		t.Error("should match user.project")
	}
}

func TestRuleEvaluate_ResourceSensitivity(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"resource.sensitivity": "confidential"},
	}
	res := Resource{Sensitivity: "confidential"}
	if !rule.Evaluate(Subject{}, res, Environment{}) {
		t.Error("should match resource.sensitivity")
	}
	res.Sensitivity = "public"
	if rule.Evaluate(Subject{}, res, Environment{}) {
		t.Error("should not match wrong sensitivity")
	}
}

func TestRuleEvaluate_EnvTime(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"env.time": "2025-01-01T12:00:00Z"},
	}
	env := Environment{Time: "2025-01-01T12:00:00Z"}
	if !rule.Evaluate(Subject{}, Resource{}, env) {
		t.Error("should match exact env.time string")
	}
}

func TestRuleEvaluate_EnvDeviceID(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"env.device_id": "mac-abc123"},
	}
	env := Environment{DeviceID: "mac-abc123"}
	if !rule.Evaluate(Subject{}, Resource{}, env) {
		t.Error("should match env.device_id")
	}
}

func TestRuleEvaluate_EnvOS(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"env.os": "linux"},
	}
	env := Environment{OS: "linux"}
	if !rule.Evaluate(Subject{}, Resource{}, env) {
		t.Error("should match env.os")
	}
}

func TestRuleEvaluate_MultipleConditions(t *testing.T) {
	rule := Rule{
		Effect: "allow",
		Conditions: map[string]interface{}{
			"user.role":             "engineer",
			"resource.sensitivity":  "internal",
			"env.os":                "linux",
		},
	}
	subj := Subject{Role: "engineer"}
	res := Resource{Sensitivity: "internal"}
	env := Environment{OS: "linux"}

	if !rule.Evaluate(subj, res, env) {
		t.Error("all conditions met, should match")
	}

	// 任一条件不满足则整体不匹配
	subj.Role = "intern"
	if rule.Evaluate(subj, res, env) {
		t.Error("one condition fails, should not match")
	}
}

func TestRuleEvaluate_RegexPath_NoMatch(t *testing.T) {
	rule := Rule{
		Effect: "allow",
		Conditions: map[string]interface{}{
			"resource.path": "regex:^/secure/.*",
		},
	}
	res := Resource{Path: "/public/file.txt"}
	if rule.Evaluate(Subject{}, res, Environment{}) {
		t.Error("path should not match regex")
	}
}

func TestRuleEvaluate_ListContains_NoMatch(t *testing.T) {
	rule := Rule{
		Effect: "allow",
		Conditions: map[string]interface{}{
			"env.ip": []interface{}{"192.168.1.1", "10.0.0.1"},
		},
	}
	env := Environment{IP: "172.16.0.1"}
	if rule.Evaluate(Subject{}, Resource{}, env) {
		t.Error("IP not in list, should not match")
	}
}

func TestRuleEvaluate_UserAttributes(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"user.department": "battery"},
	}
	subj := Subject{Attributes: map[string]interface{}{"department": "battery"}}
	if !rule.Evaluate(subj, Resource{}, Environment{}) {
		t.Error("should match user attribute 'department'")
	}
}

func TestRuleEvaluate_UserAttributes_Missing(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"user.clearance": "top_secret"},
	}
	// 未设置 Attributes
	if rule.Evaluate(Subject{}, Resource{}, Environment{}) {
		t.Error("missing attribute should not match")
	}
}

func TestRuleEvaluate_ResourceAttributes(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"resource.project": "apollo"},
	}
	res := Resource{Attributes: map[string]interface{}{"project": "apollo"}}
	if !rule.Evaluate(Subject{}, res, Environment{}) {
		t.Error("should match resource attribute")
	}
}

func TestRuleEvaluate_EnvAttributes(t *testing.T) {
	rule := Rule{
		Effect:     "allow",
		Conditions: map[string]interface{}{"env.compliance": "sox"},
	}
	env := Environment{Attributes: map[string]interface{}{"compliance": "sox"}}
	if !rule.Evaluate(Subject{}, Resource{}, env) {
		t.Error("should match env attribute")
	}
}

// =============================================================================
// MemoryEvaluator — CRUD 操作
// =============================================================================

func TestEvaluator_GetRules(t *testing.T) {
	rules := []Rule{
		{ID: "rule-1", Effect: "allow"},
		{ID: "rule-2", Effect: "deny"},
	}
	eval := NewMemoryEvaluator(rules)

	got := eval.GetRules()
	if len(got) != 2 {
		t.Errorf("GetRules count = %d, want 2", len(got))
	}
	if got[0].ID != "rule-1" || got[1].ID != "rule-2" {
		t.Error("GetRules returned wrong rules")
	}
}

func TestEvaluator_AddRule(t *testing.T) {
	eval := NewMemoryEvaluator(nil)
	eval.AddRule(Rule{ID: "added", Effect: "allow"})

	rules := eval.GetRules()
	if len(rules) != 1 {
		t.Errorf("AddRule: count = %d, want 1", len(rules))
	}
}

func TestEvaluator_UpdateRule(t *testing.T) {
	eval := NewMemoryEvaluator([]Rule{
		{ID: "r1", Effect: "allow", Conditions: map[string]interface{}{"user.role": "guest"}},
	})

	err := eval.UpdateRule("r1", Rule{ID: "r1", Effect: "deny"})
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	ctx := context.Background()
	subj := Subject{Role: "guest"}
	// 规则现在应该是 deny，但 empty conditions 的 deny 会匹配一切
	decision, _ := eval.Evaluate(ctx, subj, Resource{}, Environment{})
	if decision.Allowed {
		t.Error("updated rule should deny")
	}
}

func TestEvaluator_UpdateRule_NotFound(t *testing.T) {
	eval := NewMemoryEvaluator(nil)
	err := eval.UpdateRule("nonexistent", Rule{ID: "nonexistent", Effect: "allow"})
	if err == nil {
		t.Error("UpdateRule should return error for non-existent rule")
	}
}

func TestEvaluator_DeleteRule(t *testing.T) {
	eval := NewMemoryEvaluator([]Rule{
		{ID: "keep", Effect: "allow"},
		{ID: "remove", Effect: "deny"},
	})

	eval.DeleteRule("remove")
	rules := eval.GetRules()
	if len(rules) != 1 {
		t.Errorf("DeleteRule: count = %d, want 1", len(rules))
	}
	if rules[0].ID != "keep" {
		t.Errorf("DeleteRule: remaining rule ID = %s, want 'keep'", rules[0].ID)
	}
}

func TestEvaluator_DeleteRule_LastRule(t *testing.T) {
	eval := NewMemoryEvaluator([]Rule{{ID: "only", Effect: "allow"}})
	eval.DeleteRule("only")
	if len(eval.GetRules()) != 0 {
		t.Error("DeleteRule last rule: should be empty")
	}
}

// =============================================================================
// MemoryEvaluator — 决策行为
// =============================================================================

func TestEvaluator_DefaultDeny(t *testing.T) {
	// 没有规则 → 默认拒绝
	eval := NewMemoryEvaluator(nil)
	ctx := context.Background()
	decision, err := eval.Evaluate(ctx, Subject{}, Resource{}, Environment{})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Error("empty rules should default to deny")
	}
}

func TestEvaluator_FirstMatchWins(t *testing.T) {
	rules := []Rule{
		{ID: "allow-guests", Effect: "allow", Conditions: map[string]interface{}{"user.role": "guest"}},
		{ID: "deny-guests", Effect: "deny", Conditions: map[string]interface{}{"user.role": "guest"}},
	}
	eval := NewMemoryEvaluator(rules)
	ctx := context.Background()
	decision, _ := eval.Evaluate(ctx, Subject{Role: "guest"}, Resource{}, Environment{})
	if !decision.Allowed {
		t.Error("first matching rule should win: expected allow")
	}
}

func TestEvaluator_ExplicitDenyOverrides(t *testing.T) {
	// deny 规则排在 allow 之前
	rules := []Rule{
		{ID: "deny-all-battery", Effect: "deny", Conditions: map[string]interface{}{"user.project": "battery"}},
		{ID: "allow-engineers", Effect: "allow", Conditions: map[string]interface{}{"user.role": "engineer"}},
	}
	eval := NewMemoryEvaluator(rules)
	ctx := context.Background()
	subj := Subject{Role: "engineer", Project: "battery"}
	decision, _ := eval.Evaluate(ctx, subj, Resource{}, Environment{})
	if decision.Allowed {
		t.Error("deny rule first should reject regardless of later allow")
	}
}

func TestEvaluator_RestrictionsPassThrough(t *testing.T) {
	rules := []Rule{
		{
			ID:           "allow-with-restrictions",
			Effect:       "allow",
			Conditions:   map[string]interface{}{"user.role": "supplier"},
			Restrictions: []string{"no_print", "watermark"},
		},
	}
	eval := NewMemoryEvaluator(rules)
	ctx := context.Background()
	decision, _ := eval.Evaluate(ctx, Subject{Role: "supplier"}, Resource{}, Environment{})
	if !decision.Allowed {
		t.Fatal("expected allowed")
	}
	if len(decision.Restrictions) != 2 {
		t.Errorf("restrictions count = %d, want 2", len(decision.Restrictions))
	}
}

func TestEvaluator_UpdateRules(t *testing.T) {
	eval := NewMemoryEvaluator([]Rule{
		{ID: "old-rule", Effect: "deny", Conditions: map[string]interface{}{}},
	})
	ctx := context.Background()
	decision, _ := eval.Evaluate(ctx, Subject{Role: "admin"}, Resource{}, Environment{})
	if decision.Allowed {
		t.Fatal("old rule should deny everything")
	}

	eval.UpdateRules([]Rule{
		{ID: "new-rule", Effect: "allow", Conditions: map[string]interface{}{}},
	})
	decision, _ = eval.Evaluate(ctx, Subject{Role: "admin"}, Resource{}, Environment{})
	if !decision.Allowed {
		t.Error("new rules should allow")
	}
}

// =============================================================================
// LoadRulesFromFile
// =============================================================================

func TestLoadRulesFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "test_rules.json")

	content := `[
		{"id": "r1", "effect": "allow",
		 "conditions": {"user.role": "admin"},
		 "restrictions": ["watermark"]},
		{"id": "r2", "effect": "deny",
		 "conditions": {}}
	]`
	if err := os.WriteFile(rulesPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFromFile(rulesPath)
	if err != nil {
		t.Fatalf("LoadRulesFromFile failed: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("loaded %d rules, want 2", len(rules))
	}
	if rules[0].ID != "r1" || rules[0].Effect != "allow" {
		t.Error("first rule not loaded correctly")
	}
	if len(rules[0].Restrictions) != 1 || rules[0].Restrictions[0] != "watermark" {
		t.Error("restrictions not loaded correctly")
	}
}

func TestLoadRulesFromFile_NotFound(t *testing.T) {
	_, err := LoadRulesFromFile("/nonexistent/path/rules.json")
	if err == nil {
		t.Error("should return error for non-existent file")
	}
}

func TestEvaluator_LoadRulesFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "eval_rules.json")
	content := `[{"id": "from-file", "effect": "allow", "conditions": {"user.id": "eve"}}]`
	os.WriteFile(rulesPath, []byte(content), 0644)

	eval := NewMemoryEvaluator(nil)
	err := eval.LoadRulesFromFile(rulesPath)
	if err != nil {
		t.Fatalf("LoadRulesFromFile on evaluator failed: %v", err)
	}

	ctx := context.Background()
	decision, _ := eval.Evaluate(ctx, Subject{ID: "eve"}, Resource{}, Environment{})
	if !decision.Allowed {
		t.Error("evaluator should use loaded rules")
	}
}

// =============================================================================
// 模型 — 零值结构体
// =============================================================================

func TestSubject_ZeroValue(t *testing.T) {
	s := Subject{}
	if s.ID != "" || s.Role != "" || s.Type != "" {
		t.Error("zero Subject should have empty fields")
	}
}

func TestDecision_ZeroValue(t *testing.T) {
	d := Decision{}
	if d.Allowed {
		t.Error("zero Decision should be denied by default")
	}
	if d.Restrictions != nil {
		t.Error("zero Decision should have nil Restrictions")
	}
}
