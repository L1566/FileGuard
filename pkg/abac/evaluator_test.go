package abac

import (
	"context"
	"testing"
)

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
