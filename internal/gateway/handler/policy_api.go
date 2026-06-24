package handler

import (
	"encoding/json"
	"net/http"

	"github.com/L1566/FileGuard/pkg/abac"
	httputil "github.com/L1566/FileGuard/pkg/http"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/gorilla/mux"
)

type PolicyAPI struct {
	evaluator   *abac.MemoryEvaluator
	rulesFile   string            // 策略文件路径，用于持久化
	ruleWatcher *abac.RuleWatcher // 热加载监听器，持久化时暂停避免冗余重载
}

func NewPolicyAPI(evaluator *abac.MemoryEvaluator, rulesFile string, watcher *abac.RuleWatcher) *PolicyAPI {
	return &PolicyAPI{evaluator: evaluator, rulesFile: rulesFile, ruleWatcher: watcher}
}

// GetRules 获取所有规则
func (p *PolicyAPI) GetRules(w http.ResponseWriter, r *http.Request) {
	// MemoryEvaluator 需要暴露 GetRules 方法（稍后添加）
	rules := p.evaluator.GetRules()
	httputil.Success(w, rules)
}

// persist 将当前内存规则写回文件。写入前暂停热加载监听避免触发冗余重载。
func (p *PolicyAPI) persist() {
	if p.rulesFile == "" {
		return
	}
	if p.ruleWatcher != nil {
		p.ruleWatcher.Pause()
		defer p.ruleWatcher.Resume()
	}
	if err := abac.SaveRulesToFile(p.rulesFile, p.evaluator.GetRules()); err != nil {
		logger.Errorf("Failed to persist rules to %s: %v", p.rulesFile, err)
	}
}

// AddRule 添加规则
func (p *PolicyAPI) AddRule(w http.ResponseWriter, r *http.Request) {
	var rule abac.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		httputil.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := p.evaluator.AddRule(rule); err != nil {
		httputil.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	p.persist()
	httputil.Success(w, map[string]string{"status": "added"})
}

// UpdateRule 更新规则
func (p *PolicyAPI) UpdateRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ruleID := vars["id"]
	var rule abac.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		httputil.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := p.evaluator.UpdateRule(ruleID, rule); err != nil {
		httputil.Error(w, http.StatusNotFound, err.Error())
		return
	}
	p.persist()
	httputil.Success(w, map[string]string{"status": "updated"})
}

// DeleteRule 删除规则
func (p *PolicyAPI) DeleteRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ruleID := vars["id"]
	p.evaluator.DeleteRule(ruleID)
	p.persist()
	httputil.Success(w, map[string]string{"status": "deleted"})
}
