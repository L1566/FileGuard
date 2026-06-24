package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/L1566/FileGuard/pkg/logger"
)

// FileLogger 将审计事件写入 JSON 行文件
type FileLogger struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	logPath string // 日志文件路径，供 Query 读取
}

// NewFileLogger 创建文件审计日志，logPath 为输出文件路径（如 /var/log/fileguard/audit.log）
func NewFileLogger(logPath string) (*FileLogger, error) {
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileLogger{
		file:    f,
		encoder: json.NewEncoder(f),
		logPath: logPath,
	}, nil
}

// Log 实现 Logger 接口
func (l *FileLogger) Log(ctx context.Context, event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.encoder.Encode(event); err != nil {
		logger.Errorf("Failed to write audit log: %v", err)
		return err
	}
	return nil
}

// Query 从 JSON Lines 文件中查询审计事件，支持时间范围、主题、资源和事件类型过滤以及分页。
// 文件不存在时返回空切片而非错误。
func (l *FileLogger) Query(ctx context.Context, filter Filter) ([]AuditEvent, error) {
	f, err := os.Open(l.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var matched []AuditEvent
	decoder := json.NewDecoder(f)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var event AuditEvent
		if err := decoder.Decode(&event); err != nil {
			break // EOF or malformed line — stop reading
		}

		if !l.matchFilter(&event, filter) {
			continue
		}
		matched = append(matched, event)
	}

	// 按时间戳倒序排列（最新在前）
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})

	// 应用分页
	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return nil, nil
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}

	return matched, nil
}

// matchFilter 检查事件是否匹配过滤条件。空 filter 字段表示"匹配所有"。
func (l *FileLogger) matchFilter(event *AuditEvent, f Filter) bool {
	if f.StartTime != nil && event.Timestamp.Before(*f.StartTime) {
		return false
	}
	if f.EndTime != nil && event.Timestamp.After(*f.EndTime) {
		return false
	}
	if f.SubjectID != "" && event.Subject.ID != f.SubjectID {
		return false
	}
	if f.ResourceID != "" && event.Resource.Path != f.ResourceID {
		return false
	}
	if f.EventType != "" && event.EventType != f.EventType {
		return false
	}
	return true
}

// Close 关闭文件
func (l *FileLogger) Close() error {
	return l.file.Close()
}
