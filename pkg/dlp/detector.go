package dlp

import (
	"bytes"
	"context"
	"strings"
)

// Finding 检测结果
type Finding struct {
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Sensitivity string `json:"sensitivity"`
	Action      string `json:"action"`
	Matched     string `json:"matched"` // 匹配到的内容片段
}

// Detector DLP 检测器
type Detector struct {
	ruleSet *RuleSet
}

func NewDetector(ruleSet *RuleSet) *Detector {
	return &Detector{ruleSet: ruleSet}
}

// Detect 检测内容，返回所有匹配的规则结果
func (d *Detector) Detect(ctx context.Context, content []byte) ([]Finding, error) {
	rules := d.ruleSet.GetRules()
	var findings []Finding
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if d.matchRule(content, rule) {
			findings = append(findings, Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Sensitivity: rule.Sensitivity,
				Action:      rule.Action,
				Matched:     rule.Pattern,
			})
		}
	}
	return findings, nil
}

func (d *Detector) matchRule(content []byte, rule Rule) bool {
	if rule.IsRegex {
		d.ruleSet.mu.RLock()
		re, ok := d.ruleSet.regexCache[rule.ID]
		d.ruleSet.mu.RUnlock()
		if ok && re != nil {
			return re.Match(content)
		}
		return false
	}
	// 关键词匹配（简单包含）
	return bytes.Contains(bytes.ToLower(content), []byte(strings.ToLower(rule.Pattern)))
}
