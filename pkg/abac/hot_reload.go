package abac

import (
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/fsnotify/fsnotify"
)

// WatchRuleFile 监听规则文件变化，自动重新加载
func WatchRuleFile(evaluator *MemoryEvaluator, filePath string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					logger.Infof("Rule file changed, reloading: %s", filePath)
					if err := evaluator.LoadRulesFromFile(filePath); err != nil {
						logger.Errorf("Failed to reload rules: %v", err)
					} else {
						logger.Info("Rules reloaded successfully")
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Errorf("Rule file watcher error: %v", err)
			}
		}
	}()
	return watcher.Add(filePath)
}
