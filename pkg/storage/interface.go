package storage

import (
	"context"
	"io"
)

// FileInfo 文件元信息
type FileInfo struct {
	ID         string            `json:"id"`   // 文件唯一标识（可设为路径哈希）
	Path       string            `json:"path"` // 相对路径或绝对路径
	Size       int64             `json:"size"`
	ModifiedAt int64             `json:"modified_at"` // Unix 时间戳
	IsDir      bool              `json:"is_dir"`
	Metadata   map[string]string `json:"metadata"` // 自定义元数据，如敏感等级、所有者等
}

// Storage 统一存储接口
type Storage interface {
	// Get 获取文件内容流
	Get(ctx context.Context, path string) (io.ReadCloser, error)

	// Put 写入文件内容，metadata 为自定义元数据
	Put(ctx context.Context, path string, reader io.Reader, metadata map[string]string) error

	// Delete 删除文件
	Delete(ctx context.Context, path string) error

	// Stat 获取文件元信息
	Stat(ctx context.Context, path string) (FileInfo, error)

	// List 列出目录下的文件（非递归）
	List(ctx context.Context, dirPath string) ([]FileInfo, error)

	// Move 移动/重命名文件
	Move(ctx context.Context, src, dst string) error
}
