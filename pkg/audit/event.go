package audit

import (
	"time"

	"github.com/L1566/FileGuard/pkg/abac"
)

// EventType 操作类型
type EventType string

const (
	EventAccess           EventType = "access"
	EventDownload         EventType = "download"
	EventUpload           EventType = "upload"
	EventDelete           EventType = "delete"
	EventMove             EventType = "move"
	EventPermissionChange EventType = "permission_change"
)

// AuditEvent 审计事件结构
type AuditEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   EventType              `json:"event_type"`
	Subject     abac.Subject           `json:"subject"`
	Resource    abac.Resource          `json:"resource"`
	Environment abac.Environment       `json:"environment"`
	Decision    abac.Decision          `json:"decision"`
	Result      string                 `json:"result"` // success, failure
	Details     map[string]interface{} `json:"details"`
}
