package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// 测试辅助函数
// =============================================================================

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fileguard-storage-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func readAll(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// 创建临时目录并返回 Storage 接口（用于通用测试）
func newTestFS(t *testing.T) (Storage, string) {
	t.Helper()
	dir := tempDir(t)
	fs, err := NewLocalFileSystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fs, dir
}

// 创建 *LocalFileSystem 具体类型（用于需要访问内部方法的测试）
func newTestLFS(t *testing.T) (*LocalFileSystem, string) {
	t.Helper()
	dir := tempDir(t)
	fs, err := NewLocalFileSystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fs, dir
}

// =============================================================================
// NewLocalFileSystem
// =============================================================================

func TestNewLocalFileSystem(t *testing.T) {
	dir := tempDir(t)
	fs, err := NewLocalFileSystem(dir)
	if err != nil {
		t.Fatalf("NewLocalFileSystem failed: %v", err)
	}
	if fs == nil {
		t.Fatal("expected non-nil filesystem")
	}

	// 验证目录已创建
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("root dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("root is not a directory")
	}
}

func TestNewLocalFileSystem_ParentCreated(t *testing.T) {
	dir := filepath.Join(tempDir(t), "deep", "nested", "storage")
	fs, err := NewLocalFileSystem(dir)
	if err != nil {
		t.Fatalf("NewLocalFileSystem with nested path failed: %v", err)
	}
	if fs == nil {
		t.Fatal("expected non-nil filesystem")
	}
}

// =============================================================================
// Put + Get 往返测试
// =============================================================================

func TestPutAndGet(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestLFS(t)

	content := "hello, fileguard!"
	path := "docs/secret.txt"
	meta := map[string]string{
		"encrypted": "true",
		"key_id":    "key-001",
	}

	// Put
	err := fs.Put(ctx, path, strings.NewReader(content), meta)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get
	rc, err := fs.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got := readAll(t, rc); got != content {
		t.Errorf("Get content = %q, want %q", got, content)
	}

	// 验证 .meta 文件存在
	metaPath := fs.metaPath(path)
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Errorf(".meta file not created at %s", metaPath)
	}
}

func TestPut_NilMetadata(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	err := fs.Put(ctx, "nil-meta.txt", strings.NewReader("data"), nil)
	if err != nil {
		t.Fatalf("Put with nil metadata failed: %v", err)
	}

	info, err := fs.Stat(ctx, "nil-meta.txt")
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Metadata == nil {
		t.Error("expected non-nil metadata after Put with nil")
	}
}

func TestPut_SubdirectoryAutoCreated(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	err := fs.Put(ctx, "a/b/c/d/file.txt", strings.NewReader("deep"), nil)
	if err != nil {
		t.Fatalf("Put in deep subdirectory failed: %v", err)
	}

	rc, err := fs.Get(ctx, "a/b/c/d/file.txt")
	if err != nil {
		t.Fatalf("Get from deep subdirectory failed: %v", err)
	}
	if got := readAll(t, rc); got != "deep" {
		t.Errorf("Get content = %q, want %q", got, "deep")
	}
}

// =============================================================================
// Get 错误场景
// =============================================================================

func TestGet_NotFound(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	_, err := fs.Get(ctx, "nonexistent.txt")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// Stat
// =============================================================================

func TestStat(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	meta := map[string]string{"author": "alice", "version": "1"}
	fs.Put(ctx, "stats.txt", strings.NewReader("stat-content"), meta)

	info, err := fs.Stat(ctx, "stats.txt")
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Path != "stats.txt" {
		t.Errorf("Path = %q, want %q", info.Path, "stats.txt")
	}
	if info.Size != 12 {
		t.Errorf("Size = %d, want 12", info.Size)
	}
	if info.IsDir {
		t.Error("expected IsDir = false")
	}
	if info.Metadata["author"] != "alice" {
		t.Errorf("Metadata[author] = %q, want %q", info.Metadata["author"], "alice")
	}
	if info.Metadata["version"] != "1" {
		t.Errorf("Metadata[version] = %q, want %q", info.Metadata["version"], "1")
	}
}

func TestStat_NotFound(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	_, err := fs.Stat(ctx, "no-such-file")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestStat_MissingMetaFile(t *testing.T) {
	ctx := context.Background()
	fs, root := newTestLFS(t)

	// 直接创建文件（绕过 Put，不生成 .meta）
	fullPath := filepath.Join(root, "no-meta.txt")
	os.WriteFile(fullPath, []byte("no metadata"), 0644)

	info, err := fs.Stat(ctx, "no-meta.txt")
	if err != nil {
		t.Fatalf("Stat should succeed even without .meta: %v", err)
	}
	if len(info.Metadata) != 0 {
		t.Errorf("expected empty metadata, got %v", info.Metadata)
	}
}

// =============================================================================
// Delete
// =============================================================================

func TestDelete(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestLFS(t)

	fs.Put(ctx, "to-delete.txt", strings.NewReader("delete me"), map[string]string{"temp": "true"})

	// 删除
	err := fs.Delete(ctx, "to-delete.txt")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 验证文件已删除
	_, err = fs.Get(ctx, "to-delete.txt")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}

	// 验证 .meta 也已删除
	metaPath := fs.metaPath("to-delete.txt")
	if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
		t.Error(".meta file should be deleted")
	}
}

func TestDelete_NotFound(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	// 删除不存在的文件应该不报错
	err := fs.Delete(ctx, "ghost.txt")
	if err != nil {
		t.Errorf("Delete non-existent file should not error, got %v", err)
	}
}

// =============================================================================
// List
// =============================================================================

func TestList(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	// 创建多个文件
	fs.Put(ctx, "dir/a.txt", strings.NewReader("a"), nil)
	fs.Put(ctx, "dir/b.txt", strings.NewReader("b"), nil)
	fs.Put(ctx, "dir/c.txt", strings.NewReader("c"), nil)

	entries, err := fs.List(ctx, "dir")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("List count = %d, want 3", len(entries))
	}

	// 验证不包含 .meta 文件
	for _, e := range entries {
		if filepath.Ext(e.Path) == ".meta" {
			t.Errorf("List should skip .meta files, got %s", e.Path)
		}
	}
}

func TestList_NotFound(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	_, err := fs.List(ctx, "no-such-dir")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestList_EmptyDir(t *testing.T) {
	ctx := context.Background()
	fs, root := newTestLFS(t)

	// 创建空目录
	os.MkdirAll(filepath.Join(root, "empty-dir"), 0755)

	entries, err := fs.List(ctx, "empty-dir")
	if err != nil {
		t.Fatalf("List empty dir failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List empty dir = %d entries, want 0", len(entries))
	}
}

// =============================================================================
// Move
// =============================================================================

func TestMove(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	meta := map[string]string{"moved": "yes"}
	fs.Put(ctx, "old/file.txt", strings.NewReader("movable"), meta)

	err := fs.Move(ctx, "old/file.txt", "new/file.txt")
	if err != nil {
		t.Fatalf("Move failed: %v", err)
	}

	// 旧位置应不存在
	_, err = fs.Get(ctx, "old/file.txt")
	if err != ErrNotFound {
		t.Errorf("old file should not exist after move, got %v", err)
	}

	// 新位置应有内容
	rc, err := fs.Get(ctx, "new/file.txt")
	if err != nil {
		t.Fatalf("new file should exist after move: %v", err)
	}
	if got := readAll(t, rc); got != "movable" {
		t.Errorf("moved content = %q, want %q", got, "movable")
	}

	// 元数据应迁移
	info, err := fs.Stat(ctx, "new/file.txt")
	if err != nil {
		t.Fatalf("Stat after move failed: %v", err)
	}
	if info.Metadata["moved"] != "yes" {
		t.Error("metadata should be preserved after move")
	}
}

// =============================================================================
// 并发安全测试
// =============================================================================

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	const goroutines = 20
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			path := "concurrent/file.txt"
			err := fs.Put(ctx, path, strings.NewReader("concurrent"), nil)
			if err != nil {
				errCh <- err
				return
			}
			_, err = fs.Stat(ctx, path)
			errCh <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent operation failed: %v", err)
		}
	}
}

// =============================================================================
// 大文件与二进制数据往返
// =============================================================================

func TestPutGet_BinaryContent(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	// 包含 null 字节的二进制数据
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x00, 0x89, 0x50, 0x4E, 0x47}
	fs.Put(ctx, "binary.bin", strings.NewReader(string(data)), nil)

	rc, err := fs.Get(ctx, "binary.bin")
	if err != nil {
		t.Fatalf("Get binary failed: %v", err)
	}
	got := readAll(t, rc)
	if len(got) != len(data) {
		t.Errorf("binary content length = %d, want %d", len(got), len(data))
	}
	for i, b := range []byte(got) {
		if b != data[i] {
			t.Errorf("binary mismatch at byte %d: got 0x%02X, want 0x%02X", i, b, data[i])
		}
	}
}

func TestPutGet_LargeContent(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestFS(t)

	// ~1MB 文件
	content := strings.Repeat("FileGuard-", 100*1024)
	fs.Put(ctx, "large.txt", strings.NewReader(content), nil)

	rc, err := fs.Get(ctx, "large.txt")
	if err != nil {
		t.Fatalf("Get large file failed: %v", err)
	}
	got := readAll(t, rc)
	if got != content {
		t.Errorf("large content length = %d, want %d", len(got), len(content))
	}
}

// =============================================================================
// 接口兼容性：LocalFileSystem 实现 Storage
// =============================================================================

func TestLocalFileSystem_ImplementsStorage(t *testing.T) {
	fs, err := NewLocalFileSystem(tempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	// 编译时验证：可以赋值给 Storage 接口
	var _ Storage = fs
}

// =============================================================================
// S3 Stub 测试
// =============================================================================

func TestS3Storage_NotImplemented(t *testing.T) {
	s3, err := NewS3Storage("localhost:9000", "us-east-1", "test-bucket")
	if err != ErrNotImplemented {
		t.Errorf("NewS3Storage should return ErrNotImplemented, got %v", err)
	}
	if s3 != nil {
		t.Error("NewS3Storage should return nil storage")
	}
}
