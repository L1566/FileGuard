package risk

import (
	"fmt"
	"sync"
	"time"
)

// hourBucket 一个小时的访问统计
type hourBucket struct {
	accessCount int
	uniqueFiles map[string]struct{}
}

// bucketKey 格式化 bucket 键
func bucketKey(userID string, t time.Time) string {
	return fmt.Sprintf("%s|%s", userID, t.Format("2006010215"))
}

// BehaviorTracker 每小时用户行为追踪器（线程安全，内存存储）
type BehaviorTracker struct {
	mu      sync.RWMutex
	buckets map[string]*hourBucket
}

// NewBehaviorTracker 创建行为追踪器
func NewBehaviorTracker() *BehaviorTracker {
	return &BehaviorTracker{
		buckets: make(map[string]*hourBucket),
	}
}

// RecordAccess 记录一次文件访问。每次文件操作后调用。
func (b *BehaviorTracker) RecordAccess(userID, filePath string) {
	now := time.Now()
	key := bucketKey(userID, now)

	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[key]
	if !ok {
		bucket = &hourBucket{uniqueFiles: make(map[string]struct{})}
		b.buckets[key] = bucket
	}
	bucket.accessCount++
	bucket.uniqueFiles[filePath] = struct{}{}

	// 清理 2 小时前的旧 bucket
	cutoff := now.Add(-2 * time.Hour).Format("2006010215")
	for k := range b.buckets {
		if k < cutoff {
			delete(b.buckets, k)
		}
	}
}

// GetHourlyStats 获取指定用户当前小时的访问统计
func (b *BehaviorTracker) GetHourlyStats(userID string) (accessCount int, uniqueFiles int) {
	key := bucketKey(userID, time.Now())

	b.mu.RLock()
	defer b.mu.RUnlock()

	if bucket, ok := b.buckets[key]; ok {
		return bucket.accessCount, len(bucket.uniqueFiles)
	}
	return 0, 0
}
