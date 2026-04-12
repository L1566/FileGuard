package monitor

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/fsnotify/fsnotify"
)

type EventType string

const (
	Create EventType = "CREATE"
	Write  EventType = "WRITE"
	Remove EventType = "REMOVE"
	Rename EventType = "RENAME"
)

type FileEvent struct {
	Type    EventType
	Path    string
	OldPath string // for rename
}

type Monitor struct {
	watcher *fsnotify.Watcher
	events  chan FileEvent
	done    chan struct{}
	mu      sync.Mutex
	watches map[string]bool
}

func NewMonitor() (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Monitor{
		watcher: watcher,
		events:  make(chan FileEvent, 100),
		done:    make(chan struct{}),
		watches: make(map[string]bool),
	}, nil
}

// AddPath 添加监控目录（递归子目录）
func (m *Monitor) AddPath(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := m.watcher.Add(path); err != nil {
				logger.Warnf("Failed to watch %s: %v", path, err)
			} else {
				m.mu.Lock()
				m.watches[path] = true
				m.mu.Unlock()
				logger.Debugf("Watching directory: %s", path)
			}
		}
		return nil
	})
}

// Start 启动监控循环
func (m *Monitor) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case event, ok := <-m.watcher.Events:
				if !ok {
					return
				}
				m.handleEvent(event)
			case err, ok := <-m.watcher.Errors:
				if !ok {
					return
				}
				logger.Errorf("Watcher error: %v", err)
			case <-ctx.Done():
				m.Stop()
				return
			case <-m.done:
				return
			}
		}
	}()
}

func (m *Monitor) handleEvent(event fsnotify.Event) {
	var evType EventType
	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		evType = Create
		// 如果是新目录，自动添加监控
		if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
			m.AddPath(event.Name)
		}
	case event.Op&fsnotify.Write == fsnotify.Write:
		evType = Write
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		evType = Remove
		m.mu.Lock()
		delete(m.watches, event.Name)
		m.mu.Unlock()
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		evType = Rename
		m.mu.Lock()
		delete(m.watches, event.Name)
		m.mu.Unlock()
	default:
		return
	}
	m.events <- FileEvent{
		Type: evType,
		Path: event.Name,
	}
}

// Events 返回事件通道
func (m *Monitor) Events() <-chan FileEvent {
	return m.events
}

// Stop 停止监控
func (m *Monitor) Stop() {
	m.watcher.Close()
	close(m.done)
}
