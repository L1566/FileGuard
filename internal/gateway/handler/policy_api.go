package handler

import (
	"encoding/json"
	"net/http"

	"github.com/L1566/FileGuard/pkg/abac"
	httputil "github.com/L1566/FileGuard/pkg/http"
	"github.com/gorilla/mux"
)

type PolicyAPI struct {
	evaluator *abac.MemoryEvaluator
}

func NewPolicyAPI(evaluator *abac.MemoryEvaluator) *PolicyAPI {
	return &PolicyAPI{evaluator: evaluator}
}

// GetRules 获取所有规则
func (p *PolicyAPI) GetRules(w http.ResponseWriter, r *http.Request) {
	// MemoryEvaluator 需要暴露 GetRules 方法（稍后添加）
	rules := p.evaluator.GetRules()
	httputil.Success(w, rules)
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
	httputil.Success(w, map[string]string{"status": "updated"})
}

// DeleteRule 删除规则
func (p *PolicyAPI) DeleteRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ruleID := vars["id"]
	p.evaluator.DeleteRule(ruleID)
	httputil.Success(w, map[string]string{"status": "deleted"})
}
