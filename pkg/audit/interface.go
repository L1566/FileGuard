package audit

import (
	"context"
	"time"
)

// Filter 查询过滤条件
type Filter struct {
	StartTime  *time.Time
	EndTime    *time.Time
	SubjectID  string
	ResourceID string
	EventType  EventType
	Limit      int
	Offset     int
}

// Logger 审计日志记录器接口
type Logger interface {
	// Log 记录一个审计事件
	Log(ctx context.Context, event AuditEvent) error

	// Query 查询审计日志（可选实现，初期可返回空）
	Query(ctx context.Context, filter Filter) ([]AuditEvent, error)
}
