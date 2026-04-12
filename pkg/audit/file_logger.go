package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/L1566/FileGuard/pkg/logger"
)

// FileLogger 将审计事件写入 JSON 行文件
type FileLogger struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
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

// Query 简单实现：返回空，实际可解析文件实现（初期不要求）
func (l *FileLogger) Query(ctx context.Context, filter Filter) ([]AuditEvent, error) {
	return nil, nil
}

// Close 关闭文件
func (l *FileLogger) Close() error {
	return l.file.Close()
}
