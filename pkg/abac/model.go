package abac

// Subject 访问主体（用户、设备等）
type Subject struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // user, device, service
	Role       string                 `json:"role"`
	Project    string                 `json:"project"`    // 所属项目
	Attributes map[string]interface{} `json:"attributes"` // 扩展属性
}

// Resource 被访问的资源（文件）
type Resource struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // file, folder
	Path        string                 `json:"path"`
	Sensitivity string                 `json:"sensitivity"` // public, internal, confidential, top_secret
	Tags        []string               `json:"tags"`
	Attributes  map[string]interface{} `json:"attributes"`
}

// Environment 访问环境
type Environment struct {
	Time       string                 `json:"time"` // ISO8601 时间
	IP         string                 `json:"ip"`
	DeviceID   string                 `json:"device_id"`
	OS         string                 `json:"os"`
	Attributes map[string]interface{} `json:"attributes"`
}

// Decision 评估结果
type Decision struct {
	Allowed      bool     `json:"allowed"`
	Reason       string   `json:"reason"`
	Restrictions []string `json:"restrictions"` // 如 "no_print", "no_export"
}
