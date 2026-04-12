package abac

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Rule 表示一条 ABAC 规则
type Rule struct {
	ID         string                 `json:"id"`
	Effect     string                 `json:"effect"` // allow 或 deny
	Conditions map[string]interface{} `json:"conditions"`
}

// ConditionEvaluator 评估单个条件
func (r *Rule) evaluateCondition(condKey string, condValue interface{}, subject Subject, resource Resource, env Environment) bool {
	// 支持点号路径，如 "user.role"
	parts := strings.Split(condKey, ".")
	var actual interface{}
	if parts[0] == "user" {
		actual = subject
	} else if parts[0] == "resource" {
		actual = resource
	} else if parts[0] == "env" {
		actual = env
	} else {
		// 直接查找属性
		return false
	}
	// 简化的属性获取：只支持一层，如 user.role
	if len(parts) == 2 {
		switch parts[0] {
		case "user":
			switch parts[1] {
			case "id":
				actual = subject.ID
			case "role":
				actual = subject.Role
			case "project":
				actual = subject.Project
			default:
				if val, ok := subject.Attributes[parts[1]]; ok {
					actual = val
				} else {
					return false
				}
			}
		case "resource":
			switch parts[1] {
			case "path":
				actual = resource.Path
			case "sensitivity":
				actual = resource.Sensitivity
			default:
				if val, ok := resource.Attributes[parts[1]]; ok {
					actual = val
				} else {
					return false
				}
			}
		case "env":
			switch parts[1] {
			case "time":
				actual = env.Time
			case "ip":
				actual = env.IP
			case "device_id":
				actual = env.DeviceID
			case "os":
				actual = env.OS
			default:
				if val, ok := env.Attributes[parts[1]]; ok {
					actual = val
				} else {
					return false
				}
			}
		}
	} else {
		// 复杂路径暂不支持，返回 false
		return false
	}

	// 比较
	switch v := condValue.(type) {
	case string:
		// 支持正则，格式: "regex:^/docs/.*"
		if strings.HasPrefix(v, "regex:") {
			pattern := strings.TrimPrefix(v, "regex:")
			matched, _ := regexp.MatchString(pattern, fmt.Sprintf("%v", actual))
			return matched
		}
		return fmt.Sprintf("%v", actual) == v
	case []interface{}:
		// 包含关系：actual 是否在列表中
		strActual := fmt.Sprintf("%v", actual)
		for _, item := range v {
			if fmt.Sprintf("%v", item) == strActual {
				return true
			}
		}
		return false
	default:
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", condValue)
	}
}

// Evaluate 判断规则是否匹配当前上下文
func (r *Rule) Evaluate(subject Subject, resource Resource, env Environment) bool {
	for key, value := range r.Conditions {
		if !r.evaluateCondition(key, value, subject, resource, env) {
			return false
		}
	}
	return true
}

// LoadRulesFromFile 从 JSON 文件加载规则列表
func LoadRulesFromFile(filePath string) ([]Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
