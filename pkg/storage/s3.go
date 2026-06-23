package storage

import (
	"context"
	"errors"
	"io"
)

// ErrNotImplemented 表示该存储后端尚未实现
var ErrNotImplemented = errors.New("storage backend not implemented")

// S3Storage S3/MinIO 存储后端（待实现）
//
// 计划功能：
//   - 支持 AWS S3、MinIO、阿里云 OSS 等 S3 兼容存储
//   - 分段上传大文件
//   - 服务端加密 (SSE-S3 / SSE-KMS)
//   - 预签名 URL 直传
//   - 对象版本管理
//
// 实现时需添加依赖：
//   - github.com/aws/aws-sdk-go-v2 或 github.com/minio/minio-go/v7
//
// 配置示例（configs/gateway.yaml）：
//
//	storage:
//	  type: s3
//	  s3:
//	    endpoint: "s3.amazonaws.com"
//	    region: "us-east-1"
//	    bucket: "fileguard-data"
//	    access_key: "${AWS_ACCESS_KEY_ID}"
//	    secret_key: "${AWS_SECRET_ACCESS_KEY}"
type S3Storage struct {
	endpoint string
	region   string
	bucket   string
}

// NewS3Storage 创建 S3 存储实例（当前为占位实现）
func NewS3Storage(endpoint, region, bucket string) (*S3Storage, error) {
	return nil, ErrNotImplemented
}

// Get 从 S3 获取文件内容流
func (s *S3Storage) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	return nil, ErrNotImplemented
}

// Put 上传文件到 S3 并保存元数据
func (s *S3Storage) Put(ctx context.Context, path string, reader io.Reader, metadata map[string]string) error {
	return ErrNotImplemented
}

// Delete 从 S3 删除文件
func (s *S3Storage) Delete(ctx context.Context, path string) error {
	return ErrNotImplemented
}

// Stat 获取 S3 对象的元信息
func (s *S3Storage) Stat(ctx context.Context, path string) (FileInfo, error) {
	return FileInfo{}, ErrNotImplemented
}

// List 列出 S3 前缀下的对象
func (s *S3Storage) List(ctx context.Context, dirPath string) ([]FileInfo, error) {
	return nil, ErrNotImplemented
}

// Move 在 S3 中移动/重命名对象（COPY + DELETE）
func (s *S3Storage) Move(ctx context.Context, src, dst string) error {
	return ErrNotImplemented
}
