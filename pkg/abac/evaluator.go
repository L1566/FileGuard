package abac

import (
	"context"
	"errors"
	"sync"
)

// Evaluator 策略评估器接口
type Evaluator interface {
	Evaluate(ctx context.Context, subject Subject, resource Resource, env Environment) (Decision, error)
}

// MemoryEvaluator 基于内存规则列表的评估器
type MemoryEvaluator struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewMemoryEvaluator 创建评估器并加载初始规则
func NewMemoryEvaluator(rules []Rule) *MemoryEvaluator {
	return &MemoryEvaluator{rules: rules}
}

// Evaluate 按顺序评估规则，返回第一个匹配的决策（默认为 deny）
func (e *MemoryEvaluator) Evaluate(ctx context.Context, subject Subject, resource Resource, env Environment) (Decision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if rule.Evaluate(subject, resource, env) {
			if rule.Effect == "allow" {
				return Decision{
					Allowed:      true,
					Reason:       "matched rule " + rule.ID,
					Restrictions: rule.Restrictions,
				}, nil
			} else if rule.Effect == "deny" {
				return Decision{
					Allowed: false,
					Reason:  "denied by rule " + rule.ID,
				}, nil
			}
		}
	}
	// 默认拒绝
	return Decision{Allowed: false, Reason: "no matching allow rule"}, nil
}

// UpdateRules 动态更新规则列表（线程安全）
func (e *MemoryEvaluator) UpdateRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// LoadRulesFromFile 从文件加载规则并更新评估器
func (e *MemoryEvaluator) LoadRulesFromFile(filePath string) error {
	rules, err := LoadRulesFromFile(filePath)
	if err != nil {
		return err
	}
	e.UpdateRules(rules)
	return nil
}

// GetRules 返回规则副本
func (e *MemoryEvaluator) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// AddRule 添加规则
func (e *MemoryEvaluator) AddRule(rule Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	return nil
}

// UpdateRule 更新规则
func (e *MemoryEvaluator) UpdateRule(ruleID string, rule Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == ruleID {
			e.rules[i] = rule
			return nil
		}
	}
	return errors.New("rule not found")
}

// DeleteRule 删除规则
func (e *MemoryEvaluator) DeleteRule(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	newRules := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		if r.ID != ruleID {
			newRules = append(newRules, r)
		}
	}
	e.rules = newRules
}
