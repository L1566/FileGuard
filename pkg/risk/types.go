package risk

import (
	"encoding/json"
	"fmt"
)

// FlexFactors 灵活解析 LLM 返回的 factors，兼容 bool 和 float64 两种类型。
// LLM 有时返回 {"time_anomaly": true}，有时返回 {"time_anomaly": 0.7}。
type FlexFactors map[string]float64

func (f *FlexFactors) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	result := make(map[string]float64, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case float64:
			result[k] = val
		case bool:
			if val {
				result[k] = 1.0
			} else {
				result[k] = 0.0
			}
		case json.Number:
			n, _ := val.Float64()
			result[k] = n
		default:
			return fmt.Errorf("factors[%s]: unsupported type %T", k, v)
		}
	}
	*f = result
	return nil
}

// EvaluateRequest 风险评分请求
type EvaluateRequest struct {
	RequestID   string             `json:"request_id"`
	Subject     SubjectContext     `json:"subject"`
	Resource    ResourceContext    `json:"resource"`
	Environment EnvironmentContext `json:"environment"`
	Context     RiskContext        `json:"context"`
}

type SubjectContext struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	Project    string `json:"project"`
	Department string `json:"department,omitempty"`
}

type ResourceContext struct {
	Path        string `json:"path"`
	Sensitivity string `json:"sensitivity"`
	Type        string `json:"type,omitempty"`
}

type EnvironmentContext struct {
	Time              string `json:"time"`
	IP                string `json:"ip"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
}

type RiskContext struct {
	RecentAccessCount1H   int    `json:"recent_access_count_1h"`
	UniqueFilesAccessed1H int    `json:"unique_files_accessed_1h"`
	IsWorkHours           bool   `json:"is_work_hours"`
	IsKnownLocation       bool   `json:"is_known_location"`
	ContentSummary        string `json:"content_summary"`
}

// EvaluateResponse 风险评分响应
type EvaluateResponse struct {
	RequestID      string             `json:"request_id"`
	RiskScore      float64            `json:"risk_score"`
	RiskLevel      string             `json:"risk_level"`
	Factors        FlexFactors        `json:"factors"`
	Recommendation string             `json:"recommendation"`
	Reason         string             `json:"reason"`
	Cached         bool               `json:"cached"`
	Model          string             `json:"model,omitempty"`
	LatencyMs      int64              `json:"latency_ms"`
}

// RiskAction 将 recommendation 和 risk_score 映射为 Gateway 动作
func (r *EvaluateResponse) RiskAction() string {
	switch r.Recommendation {
	case "deny":
		return "deny"
	case "approval":
		return "approval"
	case "mfa":
		return "mfa"
	default:
		if r.RiskScore < 0.3 {
			return "allow"
		}
		if r.RiskScore < 0.6 {
			return "mfa"
		}
		if r.RiskScore < 0.8 {
			return "approval"
		}
		return "deny"
	}
}
