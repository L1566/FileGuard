package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/L1566/FileGuard/pkg/abac"
)

func TestFileLogger_Query_TimeRange(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	events := []AuditEvent{
		{
			ID: "1", Timestamp: now.Add(-2 * time.Hour), EventType: EventAccess,
			Subject: abac.Subject{ID: "user1"}, Result: "success",
		},
		{
			ID: "2", Timestamp: now.Add(-1 * time.Hour), EventType: EventDownload,
			Subject: abac.Subject{ID: "user2"}, Result: "success",
		},
		{
			ID: "3", Timestamp: now, EventType: EventUpload,
			Subject: abac.Subject{ID: "user1"}, Resource: abac.Resource{Path: "/secret.txt"}, Result: "failure",
		},
	}

	for _, e := range events {
		if err := fl.Log(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	fl.Close()

	// 查询最近 90 分钟的事件（排除 events[0]）
	start := now.Add(-90 * time.Minute)
	results, err := fl.Query(context.Background(), Filter{StartTime: &start})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 events in time range, got %d", len(results))
	}

	// 验证降序排列（最新在前）
	if results[0].Timestamp.Before(results[1].Timestamp) {
		t.Error("results should be sorted newest-first")
	}
}

func TestFileLogger_Query_SubjectFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	events := []AuditEvent{
		{ID: "1", Timestamp: now, EventType: EventAccess, Subject: abac.Subject{ID: "alice"}},
		{ID: "2", Timestamp: now, EventType: EventAccess, Subject: abac.Subject{ID: "bob"}},
		{ID: "3", Timestamp: now, EventType: EventAccess, Subject: abac.Subject{ID: "alice"}},
	}
	for _, e := range events {
		fl.Log(context.Background(), e)
	}
	fl.Close()

	results, err := fl.Query(context.Background(), Filter{SubjectID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 events for alice, got %d", len(results))
	}
}

func TestFileLogger_Query_EventTypeFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	events := []AuditEvent{
		{ID: "1", Timestamp: now, EventType: EventDownload, Subject: abac.Subject{ID: "u1"}},
		{ID: "2", Timestamp: now, EventType: EventUpload, Subject: abac.Subject{ID: "u1"}},
	}
	for _, e := range events {
		fl.Log(context.Background(), e)
	}
	fl.Close()

	results, err := fl.Query(context.Background(), Filter{EventType: EventDownload})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 download event, got %d", len(results))
	}
	if results[0].EventType != EventDownload {
		t.Errorf("expected EventDownload, got %s", results[0].EventType)
	}
}

func TestFileLogger_Query_Pagination(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	for i := 0; i < 10; i++ {
		fl.Log(context.Background(), AuditEvent{
			ID:        string(rune('a' + i)),
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			EventType: EventAccess,
			Subject:   abac.Subject{ID: "test"},
		})
	}
	fl.Close()

	// Limit only
	results, err := fl.Query(context.Background(), Filter{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 events with limit, got %d", len(results))
	}

	// Offset + Limit
	results, err = fl.Query(context.Background(), Filter{Offset: 5, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 events after offset, got %d", len(results))
	}

	// Offset beyond total
	results, err = fl.Query(context.Background(), Filter{Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 events with large offset, got %d", len(results))
	}
}

func TestFileLogger_Query_FileNotFound(t *testing.T) {
	fl := &FileLogger{logPath: "/nonexistent/path/audit.log"}
	results, err := fl.Query(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Error("expected nil results for missing file")
	}
}

func TestFileLogger_Query_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Write a lot of events to make Query take measurable time
	now := time.Now()
	for i := 0; i < 1000; i++ {
		fl.Log(context.Background(), AuditEvent{
			ID:        string(rune(i)),
			Timestamp: now,
			EventType: EventAccess,
			Subject:   abac.Subject{ID: "bulk"},
		})
	}
	fl.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消
	_, err = fl.Query(ctx, Filter{})
	if err == nil {
		t.Error("expected context cancellation error")
	}
}

func TestFileLogger_Query_ResourceFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	fl.Log(context.Background(), AuditEvent{
		ID: "1", Timestamp: now, EventType: EventDownload,
		Subject: abac.Subject{ID: "u1"}, Resource: abac.Resource{Path: "/projects/design.pdf"},
	})
	fl.Log(context.Background(), AuditEvent{
		ID: "2", Timestamp: now, EventType: EventDownload,
		Subject: abac.Subject{ID: "u1"}, Resource: abac.Resource{Path: "/reports/finance.xlsx"},
	})
	fl.Close()

	results, err := fl.Query(context.Background(), Filter{ResourceID: "/projects/design.pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 event for resource path, got %d", len(results))
	}
	if results[0].ID != "1" {
		t.Errorf("expected event 1, got %s", results[0].ID)
	}
}

func TestFileLogger_Log_ConcurrentSafety(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	fl, err := NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()

	done := make(chan struct{})
	const goroutines = 10
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				fl.Log(context.Background(), AuditEvent{
					ID:        string(rune(id*100 + j)),
					Timestamp: time.Now(),
					EventType: EventAccess,
					Subject:   abac.Subject{ID: "concurrent"},
				})
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	// 验证文件有 1000 行
	fl.Close()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 1000 {
		t.Errorf("expected 1000 log lines, got %d", lines)
	}
}
