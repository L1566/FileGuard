package abac

import (
	"sync"

	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/fsnotify/fsnotify"
)

// RuleWatcher 管理规则文件的热加载
type RuleWatcher struct {
	watcher   *fsnotify.Watcher
	done      chan struct{}
	mu        sync.Mutex
	paused    bool
	evaluator *MemoryEvaluator
	filePath  string
}

// WatchRuleFile 监听规则文件变化并自动重载。返回 RuleWatcher 用于暂停/恢复/关闭。
func WatchRuleFile(evaluator *MemoryEvaluator, filePath string) (*RuleWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := w.Add(filePath); err != nil {
		w.Close()
		return nil, err
	}

	rw := &RuleWatcher{
		watcher:   w,
		done:      make(chan struct{}),
		evaluator: evaluator,
		filePath:  filePath,
	}
	go rw.loop()
	logger.Infof("Rule file watcher started: %s", filePath)
	return rw, nil
}

// Close 停止监听并释放资源
func (rw *RuleWatcher) Close() error {
	close(rw.done)
	return rw.watcher.Close()
}

// Pause 暂停热加载处理（策略 CRUD API 写入文件时调用以免触发冗余重载）
func (rw *RuleWatcher) Pause() {
	rw.mu.Lock()
	rw.paused = true
	rw.mu.Unlock()
}

// Resume 恢复热加载处理
func (rw *RuleWatcher) Resume() {
	rw.mu.Lock()
	rw.paused = false
	rw.mu.Unlock()
}

func (rw *RuleWatcher) loop() {
	for {
		select {
		case <-rw.done:
			return
		case event, ok := <-rw.watcher.Events:
			if !ok {
				return
			}
			rw.mu.Lock()
			p := rw.paused
			rw.mu.Unlock()
			if p {
				continue
			}
			// Write/Create: 直接写入; Rename: 编辑器原子保存（Linux）
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				logger.Infof("Rule file changed (%s), reloading: %s", event.Op, rw.filePath)
				if err := rw.evaluator.LoadRulesFromFile(rw.filePath); err != nil {
					logger.Errorf("Failed to reload rules: %v", err)
				} else {
					logger.Info("Rules reloaded successfully")
				}
			}
		case err, ok := <-rw.watcher.Errors:
			if !ok {
				return
			}
			logger.Errorf("Rule file watcher error: %v", err)
		}
	}
}
