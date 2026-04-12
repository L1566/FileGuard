package storage

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// LocalFileSystem 实现 Storage 接口
type LocalFileSystem struct {
	rootDir string // 存储的根目录
}

// NewLocalFileSystem 创建本地文件系统存储实例
func NewLocalFileSystem(rootDir string) (*LocalFileSystem, error) {
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		return nil, err
	}
	return &LocalFileSystem{rootDir: rootDir}, nil
}

// 获取文件的完整路径
func (fs *LocalFileSystem) fullPath(path string) string {
	return filepath.Join(fs.rootDir, filepath.Clean(path))
}

// 获取元数据文件路径
func (fs *LocalFileSystem) metaPath(path string) string {
	return fs.fullPath(path) + ".meta"
}

// Get 实现
func (fs *LocalFileSystem) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	full := fs.fullPath(path)
	file, err := os.Open(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return file, nil
}

// Put 实现
func (fs *LocalFileSystem) Put(ctx context.Context, path string, reader io.Reader, metadata map[string]string) error {
	full := fs.fullPath(path)
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	// 写入文件内容
	file, err := os.Create(full)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(file, reader); err != nil {
		return err
	}
	// 保存元数据
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metaFile, err := os.Create(fs.metaPath(path))
	if err != nil {
		return err
	}
	defer metaFile.Close()
	enc := json.NewEncoder(metaFile)
	return enc.Encode(metadata)
}

// Delete 实现
func (fs *LocalFileSystem) Delete(ctx context.Context, path string) error {
	full := fs.fullPath(path)
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	// 删除元数据文件（忽略不存在错误）
	_ = os.Remove(fs.metaPath(path))
	return nil
}

// Stat 实现
func (fs *LocalFileSystem) Stat(ctx context.Context, path string) (FileInfo, error) {
	full := fs.fullPath(path)
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return FileInfo{}, ErrNotFound
		}
		return FileInfo{}, err
	}
	// 读取元数据
	metadata := make(map[string]string)
	if metaFile, err := os.Open(fs.metaPath(path)); err == nil {
		defer metaFile.Close()
		json.NewDecoder(metaFile).Decode(&metadata)
	}
	return FileInfo{
		Path:       path,
		Size:       info.Size(),
		ModifiedAt: info.ModTime().Unix(),
		IsDir:      info.IsDir(),
		Metadata:   metadata,
	}, nil
}

// List 实现
func (fs *LocalFileSystem) List(ctx context.Context, dirPath string) ([]FileInfo, error) {
	full := fs.fullPath(dirPath)
	entries, err := os.ReadDir(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var result []FileInfo
	for _, entry := range entries {
		// 跳过元数据文件
		if filepath.Ext(entry.Name()) == ".meta" {
			continue
		}
		subPath := filepath.Join(dirPath, entry.Name())
		info, err := fs.Stat(ctx, subPath)
		if err != nil {
			continue
		}
		result = append(result, info)
	}
	return result, nil
}

// Move 实现
func (fs *LocalFileSystem) Move(ctx context.Context, src, dst string) error {
	srcFull := fs.fullPath(src)
	dstFull := fs.fullPath(dst)
	if err := os.MkdirAll(filepath.Dir(dstFull), 0755); err != nil {
		return err
	}
	if err := os.Rename(srcFull, dstFull); err != nil {
		return err
	}
	// 移动元数据文件
	_ = os.Rename(fs.metaPath(src), fs.metaPath(dst))
	return nil
}

// 预定义错误（与 pkg/errors 保持一致，但简单处理）
//var ErrNotFound = errors.New("file not found")
