package dlp

import (
	"encoding/json"
	"os"
	"regexp"
	"sync"
)

// Rule 表示一条 DLP 规则
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`     // 正则表达式或关键词
	IsRegex     bool   `json:"is_regex"`    // true: 正则匹配，false: 包含关键词
	Sensitivity string `json:"sensitivity"` // low, medium, high, critical
	Action      string `json:"action"`      // block, alert, log
	Enabled     bool   `json:"enabled"`
}

// RuleSet 管理 DLP 规则集
type RuleSet struct {
	mu         sync.RWMutex
	rules      []Rule
	regexCache map[string]*regexp.Regexp
}

func NewRuleSet() *RuleSet {
	return &RuleSet{
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// LoadFromFile 从 JSON 文件加载规则
func (rs *RuleSet) LoadFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = rules
	// 预编译正则
	for _, r := range rules {
		if r.IsRegex {
			if _, ok := rs.regexCache[r.ID]; !ok {
				re, err := regexp.Compile(r.Pattern)
				if err == nil {
					rs.regexCache[r.ID] = re
				}
			}
		}
	}
	return nil
}

// GetRules 返回规则副本
func (rs *RuleSet) GetRules() []Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]Rule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// AddRule 添加规则（线程安全）
func (rs *RuleSet) AddRule(rule Rule) error {
	if rule.IsRegex {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return err
		}
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append(rs.rules, rule)
	if rule.IsRegex {
		rs.regexCache[rule.ID], _ = regexp.Compile(rule.Pattern)
	}
	return nil
}

// UpdateRule 更新规则
func (rs *RuleSet) UpdateRule(ruleID string, rule Rule) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for i, r := range rs.rules {
		if r.ID == ruleID {
			rs.rules[i] = rule
			if rule.IsRegex {
				rs.regexCache[rule.ID], _ = regexp.Compile(rule.Pattern)
			} else {
				delete(rs.regexCache, rule.ID)
			}
			return nil
		}
	}
	return os.ErrNotExist
}

// DeleteRule 删除规则
func (rs *RuleSet) DeleteRule(ruleID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	newRules := make([]Rule, 0, len(rs.rules))
	for _, r := range rs.rules {
		if r.ID != ruleID {
			newRules = append(newRules, r)
		}
	}
	rs.rules = newRules
	delete(rs.regexCache, ruleID)
}
