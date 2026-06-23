package risk

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
	Factors        map[string]float64 `json:"factors"`
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
