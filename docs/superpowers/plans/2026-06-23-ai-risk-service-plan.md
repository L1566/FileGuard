# AI 动态风险评分服务 — 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增独立 Risk Service 微服务，利用云端 LLM 对文件访问请求进行实时多维风险评分，Gateway 据此动态决策。

**Architecture:** 独立 Go HTTP 服务（`cmd/riskservice`），通过 `pkg/risk/client` 与 Gateway 集成。Gateway 在 ABAC 通过后异步调用 Risk Service 获取评分，根据评分决定 allow/mfa/approval/deny。

**Tech Stack:** Go 1.25, gorilla/mux, viper, logrus, net/http (stdlib), Anthropic Claude API

---

### Task 1: 风险评分数据类型 (`pkg/risk/types.go`)

**Files:**
- Create: `pkg/risk/types.go`

- [ ] **Step 1: 编写数据类型**

```go
package risk

// EvaluateRequest 风险评分请求
type EvaluateRequest struct {
	RequestID   string             `json:"request_id"`
	Subject     SubjectContext     `json:"subject"`
	Resource    ResourceContext    `json:"resource"`
	Environment EnvironmentContext `json:"environment"`
	Context     RiskContext        `json:"context"`
}

type SubjectContext struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	Project    string `json:"project"`
	Department string `json:"department,omitempty"`
}

type ResourceContext struct {
	Path        string `json:"path"`
	Sensitivity string `json:"sensitivity"`
	Type        string `json:"type,omitempty"`
}

type EnvironmentContext struct {
	Time              string `json:"time"`
	IP                string `json:"ip"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
}

type RiskContext struct {
	RecentAccessCount1H   int    `json:"recent_access_count_1h"`
	UniqueFilesAccessed1H int    `json:"unique_files_accessed_1h"`
	IsWorkHours           bool   `json:"is_work_hours"`
	IsKnownLocation       bool   `json:"is_known_location"`
	ContentSummary        string `json:"content_summary"`
}

// EvaluateResponse 风险评分响应
type EvaluateResponse struct {
	RequestID      string             `json:"request_id"`
	RiskScore      float64            `json:"risk_score"`
	RiskLevel      string             `json:"risk_level"`
	Factors        map[string]float64 `json:"factors"`
	Recommendation string             `json:"recommendation"`
	Reason         string             `json:"reason"`
	Cached         bool               `json:"cached"`
	Model          string             `json:"model,omitempty"`
	LatencyMs      int64              `json:"latency_ms"`
}

// RiskAction 将 recommendation 映射为 Gateway 动作
func (r *EvaluateResponse) RiskAction() string {
	switch r.Recommendation {
	case "deny":
		return "deny"
	case "approval":
		return "approval"
	case "mfa":
		return "mfa"
	default:
		if r.RiskScore < 0.3 {
			return "allow"
		}
		if r.RiskScore < 0.6 {
			return "mfa"
		}
		if r.RiskScore < 0.8 {
			return "approval"
		}
		return "deny"
	}
}
```

- [ ] **Step 2: 验证编译**

Run: `go build ./pkg/risk/...`
Expected: 编译成功（仅类型定义，无依赖问题）

- [ ] **Step 3: Commit**

```bash
git add pkg/risk/types.go
git commit -m "feat(risk): add risk evaluation data types"
```

---

### Task 2: PII 脱敏引擎 (`pkg/risk/sanitizer.go` + test)

**Files:**
- Create: `pkg/risk/sanitizer.go`
- Create: `pkg/risk/sanitizer_test.go`

- [ ] **Step 1: 编写测试（TDD — 先写测试）**

```go
package risk

import "testing"

func TestSanitizeChineseID(t *testing.T) {
	tests := []struct{ input, want string }{
		{"110101199001011234", "110101****1234"},
		{"开头无身份证号", "开头无身份证号"},
		{"身份证110101199001011234在这里", "身份证110101****1234在这里"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizePhone(t *testing.T) {
	tests := []struct{ input, want string }{
		{"13812345678", "138****5678"},
		{"电话：13812345678，请记录", "电话：138****5678，请记录"},
		{"no phone here", "no phone here"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeEmail(t *testing.T) {
	tests := []struct{ input, want string }{
		{"alice@evcompany.com", "a***@evcompany.com"},
		{"发送至 bob@test.cn 即可", "发送至 b***@test.cn 即可"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeIP(t *testing.T) {
	tests := []struct{ input, want string }{
		{"IP: 192.168.1.100", "IP: 192.168.*.*"},
		{"10.0.0.1", "10.0.*.*"},
		{"no ip", "no ip"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeBankCard(t *testing.T) {
	input := "卡号6222021234567890请核对"
	want := "卡号****7890请核对"
	got := Sanitize(input)
	if got != want {
		t.Errorf("Sanitize(%q) = %q, want %q", input, got, want)
	}
}

func TestSanitizeEmpty(t *testing.T) {
	if Sanitize("") != "" {
		t.Error("empty input should return empty")
	}
}
```

- [ ] **Step 2: 运行测试（确认失败）**

Run: `go test ./pkg/risk/ -v -run TestSanitize`
Expected: FAIL — `Sanitize` 未定义

- [ ] **Step 3: 实现脱敏引擎**

```go
package risk

import "regexp"

var sanitizeRules = []struct {
	pattern *regexp.Regexp
	replace string
}{
	// 身份证号（18位）
	{regexp.MustCompile(`\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`),
		"****-ID-****"},
	// 手机号（中国大陆）
	{regexp.MustCompile(`\b1[3-9]\d{9}\b`),
		"****-PHONE-****"},
	// 邮箱
	{regexp.MustCompile(`\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b`),
		"***@$2"},
	// IP 地址（IPv4）
	{regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b`),
		"$1.$2.*.*"},
	// 银行卡号（13-19位数字）
	{regexp.MustCompile(`\b\d{13,19}\b`),
		"****-BANK-****"},
	// 中文人名（姓+1-2名）
	{regexp.MustCompile(`[\x{4e00}-\x{9fa5}]{2,4}`),
		"**"},
	// 金额（¥或$开头）
	{regexp.MustCompile(`[¥$]\d[\d,.]*`),
		"¥***"},
	// 车牌号（含新能源）
	{regexp.MustCompile(`[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警]?`),
		"**-CAR-***"},
}

// Sanitize 对输入文本执行 PII 脱敏，返回脱敏后的文本
func Sanitize(input string) string {
	if input == "" {
		return ""
	}
	result := input
	for _, rule := range sanitizeRules {
		result = rule.pattern.ReplaceAllString(result, rule.replace)
	}
	return result
}
```

- [ ] **Step 4: 运行测试（确认通过）**

Run: `go test ./pkg/risk/ -v -run TestSanitize`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/risk/sanitizer.go pkg/risk/sanitizer_test.go
git commit -m "feat(risk): add PII sanitization engine with tests"
```

---

### Task 3: Prompt 模板 (`pkg/risk/prompt.go`)

**Files:**
- Create: `pkg/risk/prompt.go`

- [ ] **Step 1: 实现 Prompt 模板**

```go
package risk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/template"
)

const systemPrompt = `你是一个企业文件访问安全分析引擎。根据用户访问上下文评估风险。
输出必须是严格的 JSON 格式，不含任何其他文本。

风险评分规则:
- 0.0~0.3 低风险: 正常工作时间、受信位置、访问频率正常
- 0.3~0.6 中风险: 轻微偏离常规模式
- 0.6~0.8 高风险: 多因素异常叠加
- 0.8~1.0 极高: 明显恶意行为

评估维度:
1. time_anomaly — 时间是否在常规工作模式内
2. location_anomaly — IP/地理位置是否受信
3. behavior_volume — 访问频率/数据量是否异常
4. content_sensitivity — 文件内容是否包含高危信息`

var userPromptTmpl = template.Must(template.New("user").Parse(`{
  "subject": {"role": "{{.Subject.Role}}", "project": "{{.Subject.Project}}"},
  "resource": {"path": "{{.Resource.Path}}", "content_summary": "{{.Context.ContentSummary}}"},
  "environment": {"time": "{{.Environment.Time}}", "is_work_hours": {{.Context.IsWorkHours}}, "is_known_location": {{.Context.IsKnownLocation}}},
  "behavior": {"recent_files_1h": {{.Context.RecentAccessCount1H}}, "unique_files_1h": {{.Context.UniqueFilesAccessed1H}}}
}

请返回 JSON: {"risk_score": <0.0-1.0>, "risk_level": "<low|medium|high|critical>", "factors": {"time_anomaly": ..., "location_anomaly": ..., "behavior_volume": ..., "content_sensitivity": ...}, "recommendation": "<allow|mfa|approval|deny>", "reason": "<中文解释>"}`))

// BuildPrompt 构造 LLM 请求的 system + user messages
func BuildPrompt(req *EvaluateRequest) (system, user string, err error) {
	var buf bytes.Buffer
	if err := userPromptTmpl.Execute(&buf, req); err != nil {
		return "", "", fmt.Errorf("prompt render: %w", err)
	}
	return systemPrompt, buf.String(), nil
}

// BuildLLMRequest 构造发给 Claude API 的完整请求体
func BuildLLMRequest(req *EvaluateRequest, model string) ([]byte, error) {
	sys, usr, err := BuildPrompt(req)
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"model":      model,
		"max_tokens": 256,
		"temperature": 0.0,
		"system":     sys,
		"messages": []map[string]string{
			{"role": "user", "content": usr},
		},
	}
	return json.Marshal(body)
}
```

- [ ] **Step 2: 验证编译**

Run: `go build ./pkg/risk/...`
Expected: 编译成功（`text/template` 为标准库）

- [ ] **Step 3: Commit**

```bash
git add pkg/risk/prompt.go
git commit -m "feat(risk): add LLM prompt template builder"
```

---

### Task 4: 评分引擎 (`pkg/risk/scorer.go`)

**Files:**
- Create: `pkg/risk/scorer.go`

- [ ] **Step 1: 添加 LRU 缓存依赖**

```bash
go get github.com/hashicorp/golang-lru/v2
```

- [ ] **Step 2: 实现评分引擎**

```go
package risk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/L1566/FileGuard/pkg/logger"
)

// Scorer 风险评分引擎
type Scorer struct {
	model      string
	apiKey     string
	httpClient *http.Client
	cache      *lru.Cache[string, *EvaluateResponse]
	ttl        time.Duration
	failCount  atomic.Int32
	mu         sync.RWMutex
	degraded   bool // 连续失败后降级标记
}

type ScorerConfig struct {
	Model      string
	APIKeyEnv  string
	Timeout    time.Duration
	MaxRetries int
	CacheSize  int
	CacheTTL   time.Duration
}

func NewScorer(cfg ScorerConfig) (*Scorer, error) {
	cache, err := lru.New[string, *EvaluateResponse](cfg.CacheSize)
	if err != nil {
		return nil, err
	}
	apiKey := os.Getenv(cfg.APIKeyEnv)
	if apiKey == "" {
		logger.Warnf("LLM API key env %s not set, risk scoring will use defaults", cfg.APIKeyEnv)
	}
	return &Scorer{
		model:  cfg.Model,
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache: cache,
		ttl:   cfg.CacheTTL,
	}, nil
}

// Evaluate 执行风险评分（优先返回缓存）
func (s *Scorer) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	// 先发脱敏
	req.Context.ContentSummary = Sanitize(req.Context.ContentSummary)

	// 查缓存
	cacheKey := s.cacheKey(req)
	if cached, ok := s.cache.Get(cacheKey); ok {
		cached.Cached = true
		return cached, nil
	}

	// 调用 LLM
	start := time.Now()
	resp, err := s.callLLM(ctx, req)
	if err != nil {
		s.failCount.Add(1)
		if s.failCount.Load() >= 3 {
			s.mu.Lock()
			s.degraded = true
			s.mu.Unlock()
			logger.Errorf("Risk scorer degraded: %d consecutive failures", s.failCount.Load())
		}
		return s.defaultResponse(), nil
	}

	// 成功后重置失败计数
	s.failCount.Store(0)
	s.mu.Lock()
	s.degraded = false
	s.mu.Unlock()

	resp.LatencyMs = time.Since(start).Milliseconds()
	resp.Model = s.model

	// 写入缓存
	s.cache.Add(cacheKey, resp)

	return resp, nil
}

// IsDegraded 检查是否处于降级状态
func (s *Scorer) IsDegraded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.degraded
}

func (s *Scorer) cacheKey(req *EvaluateRequest) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s",
		req.Subject.Role,
		req.Resource.Path,
		req.Environment.IP,
		time.Now().Truncate(s.ttl).Format(time.RFC3339),
	)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

func (s *Scorer) callLLM(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	if s.apiKey == "" {
		return s.defaultResponse(), nil
	}

	body, err := BuildLLMRequest(req, s.model)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", s.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("llm API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return parseLLMResponse(resp.Body)
}

func parseLLMResponse(r io.Reader) (*EvaluateResponse, error) {
	var llmResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(r).Decode(&llmResp); err != nil {
		return nil, fmt.Errorf("parse llm response: %w", err)
	}
	if len(llmResp.Content) == 0 {
		return nil, fmt.Errorf("empty llm response")
	}

	result := &EvaluateResponse{
		RiskScore:      0.1,
		RiskLevel:      "low",
		Recommendation: "allow",
		Reason:         "default (LLM unavailable)",
	}

	text := llmResp.Content[0].Text
	if err := json.Unmarshal([]byte(text), result); err != nil {
		// JSON 解析失败，返回安全的默认值
		logger.Warnf("Failed to parse LLM JSON response, using defaults: %v", err)
		return result, nil
	}

	// 钳位 risk_score
	if result.RiskScore < 0 {
		result.RiskScore = 0
	}
	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	}

	return result, nil
}

func (s *Scorer) defaultResponse() *EvaluateResponse {
	return &EvaluateResponse{
		RiskScore:      0.1,
		RiskLevel:      "low",
		Recommendation: "allow",
		Reason:         "risk service default (LLM unavailable)",
	}
}
```

- [ ] **Step 3: 验证编译**

Run: `go build ./pkg/risk/...`
Expected: 编译成功

- [ ] **Step 4: Commit**

```bash
git add pkg/risk/scorer.go go.mod go.sum
git commit -m "feat(risk): add LLM-based scoring engine with cache and degradation"
```

---

### Task 5: Gateway 侧客户端 (`pkg/risk/client.go`)

**Files:**
- Create: `pkg/risk/client.go`

- [ ] **Step 1: 实现 Gateway 侧轻量 HTTP 客户端**

```go
package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client Gateway 侧 Risk Service 调用客户端
type Client struct {
	serviceURL string
	httpClient *http.Client
}

// NewClient 创建风险评分客户端
func NewClient(serviceURL string, timeout time.Duration) *Client {
	return &Client{
		serviceURL: serviceURL,
		httpClient: &http.Client{Timeout: timeout},
	}
}

// Evaluate 向 Risk Service 发起评分请求
func (c *Client) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serviceURL+"/api/risk/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("risk service call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("risk service returned %d", resp.StatusCode)
	}

	var result EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &result, nil
}
```

- [ ] **Step 2: 验证编译**

Run: `go build ./pkg/risk/...`
Expected: 编译成功（纯标准库 `net/http` + `encoding/json`）

- [ ] **Step 3: Commit**

```bash
git add pkg/risk/client.go
git commit -m "feat(risk): add Gateway-side risk client"
```

---

### Task 6: 配置变更

**Files:**
- Modify: `pkg/config/config.go`
- Modify: `configs/gateway.yaml`
- Create: `configs/riskservice.yaml`

- [ ] **Step 1: 增加配置类型**

在 `pkg/config/config.go` 的 `GatewaySettings` 之后添加：

```go
// RiskSettings 风险评分设置（Gateway 侧）
type RiskSettings struct {
	Enabled    bool          `mapstructure:"enabled"`
	Mode       string        `mapstructure:"mode"`        // shadow | monitor | active
	ServiceURL string        `mapstructure:"service_url"` // e.g. localhost:8090
	CacheTTL   time.Duration `mapstructure:"cache_ttl"`   // e.g. 5m
	Timeout    time.Duration `mapstructure:"timeout"`     // e.g. 500ms
	Fallback   string        `mapstructure:"fallback"`    // allow | deny | abac_only
}

// RiskServiceConfig Risk Service 自身配置
type RiskServiceConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
	LLM     LLMSettings     `mapstructure:"llm"`
	Cache   CacheSettings   `mapstructure:"cache"`
}

type LLMSettings struct {
	Provider   string        `mapstructure:"provider"`
	Model      string        `mapstructure:"model"`
	APIKeyEnv  string        `mapstructure:"api_key_env"`
	Timeout    time.Duration `mapstructure:"timeout"`
	MaxRetries int           `mapstructure:"max_retries"`
}

type CacheSettings struct {
	MaxEntries int           `mapstructure:"max_entries"`
	TTL        time.Duration `mapstructure:"ttl"`
}
```

在 `GatewayConfig` 中添加 `Risk` 字段：

```go
// 在 GatewayConfig struct 的 Watermark 字段之后添加
Risk     RiskSettings    `mapstructure:"risk"`
```

添加 `LoadRiskService` 函数：

```go
// LoadRiskService 加载 Risk Service 配置
func LoadRiskService(configFile string) (*RiskServiceConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg RiskServiceConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

- [ ] **Step 2: 更新 gateway.yaml**

在 `configs/gateway.yaml` 末尾追加：

```yaml
risk:
  enabled: true
  mode: shadow            # shadow | monitor | active
  service_url: http://localhost:8090
  cache_ttl: 5m
  timeout: 500ms
  fallback: allow         # allow | deny | abac_only
```

- [ ] **Step 3: 创建 riskservice.yaml**

`configs/riskservice.yaml`：

```yaml
service:
  name: FileGuard-riskservice
  port: 8090

log:
  level: info
  format: text

llm:
  provider: anthropic
  model: claude-sonnet-4-6
  api_key_env: FILEGUARD_LLM_API_KEY
  timeout: 10s
  max_retries: 2

cache:
  max_entries: 10000
  ttl: 5m
```

- [ ] **Step 4: 验证编译**

Run: `go build ./pkg/config/...`
Expected: 编译成功

- [ ] **Step 5: Commit**

```bash
git add pkg/config/config.go configs/gateway.yaml configs/riskservice.yaml
git commit -m "feat(risk): add risk config types, gateway.yaml risk node, riskservice.yaml"
```

---

### Task 7: Risk Service 服务端

**Files:**
- Create: `cmd/riskservice/main.go`
- Create: `internal/riskservice/handler/evaluate.go`

- [ ] **Step 1: 实现 HTTP handler**

`internal/riskservice/handler/evaluate.go`：

```go
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/risk"
	"github.com/google/uuid"
)

// Handler Risk Service HTTP 处理器
type Handler struct {
	scorer *risk.Scorer
}

func NewHandler(scorer *risk.Scorer) *Handler {
	return &Handler{scorer: scorer}
}

// Evaluate 处理风险评分请求
func (h *Handler) Evaluate(w http.ResponseWriter, r *http.Request) {
	var req risk.EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if req.RequestID == "" {
		req.RequestID = uuid.New().String()
	}

	start := time.Now()
	resp, err := h.scorer.Evaluate(r.Context(), &req)
	if err != nil {
		logger.Warnf("Risk evaluation failed: %v", err)
		resp = &risk.EvaluateResponse{
			RequestID:      req.RequestID,
			RiskScore:      0.1,
			RiskLevel:      "low",
			Recommendation: "allow",
			Reason:         "evaluation error, defaulting to allow",
		}
	}

	resp.RequestID = req.RequestID
	resp.LatencyMs = time.Since(start).Milliseconds()

	writeJSON(w, http.StatusOK, resp)
}

// HealthCheck 健康检查
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"degraded": h.scorer.IsDegraded(),
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
```

- [ ] **Step 2: 实现服务入口**

`cmd/riskservice/main.go`：

```go
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/L1566/FileGuard/internal/riskservice/handler"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/risk"
	"github.com/gorilla/mux"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/riskservice.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadRiskService(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	scorer, err := risk.NewScorer(risk.ScorerConfig{
		Model:      cfg.LLM.Model,
		APIKeyEnv:  cfg.LLM.APIKeyEnv,
		Timeout:    cfg.LLM.Timeout,
		MaxRetries: cfg.LLM.MaxRetries,
		CacheSize:  cfg.Cache.MaxEntries,
		CacheTTL:   cfg.Cache.TTL,
	})
	if err != nil {
		logger.Fatal("Failed to create scorer: ", err)
	}

	h := handler.NewHandler(scorer)
	r := mux.NewRouter()
	r.HandleFunc("/health", h.HealthCheck).Methods("GET")
	r.HandleFunc("/api/risk/evaluate", h.Evaluate).Methods("POST")

	addr := fmt.Sprintf(":%d", cfg.Service.Port)
	logger.Infof("Starting Risk Service on %s", addr)

	go func() {
		if err := http.ListenAndServe(addr, r); err != nil {
			logger.Fatal("Server failed: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down Risk Service...")
}
```

- [ ] **Step 3: 添加 uuid 依赖**

```bash
go get github.com/google/uuid
```

- [ ] **Step 4: 验证编译**

Run: `go build ./cmd/riskservice/... ./internal/riskservice/...`
Expected: 编译成功

- [ ] **Step 5: Commit**

```bash
git add cmd/riskservice/main.go internal/riskservice/handler/evaluate.go go.mod go.sum
git commit -m "feat(risk): add Risk Service server entrypoint and HTTP handler"
```

---

### Task 8: Gateway 集成

**Files:**
- Modify: `internal/gateway/handler/file.go`
- Modify: `cmd/gateway/main.go`

- [ ] **Step 1: 注入 riskClient 到 FileHandler**

修改 `internal/gateway/handler/file.go`：

```go
// 在 FileHandler struct 中添加 riskClient 字段
type FileHandler struct {
	storage     storage.Storage
	evaluator   abac.Evaluator
	audit       audit.Logger
	kmsClient   *kms.Client
	dlpDetector *dlp.Detector
	riskClient  *risk.Client  // 新增
}

// 修改 NewFileHandler 签名
func NewFileHandler(
	storage storage.Storage,
	evaluator abac.Evaluator,
	audit audit.Logger,
	kmsClient *kms.Client,
	dlpDetector *dlp.Detector,
	riskClient *risk.Client,  // 新增
) *FileHandler {
	return &FileHandler{
		storage:    storage,
		evaluator:  evaluator,
		audit:      audit,
		kmsClient:  kmsClient,
		dlpDetector: dlpDetector,
		riskClient: riskClient,
	}
}
```

在 file.go 中添加 `evaluateRisk` 方法：

```go
import "github.com/L1566/FileGuard/pkg/risk"

// 在文件末尾添加
func (h *FileHandler) evaluateRisk(ctx context.Context, subject abac.Subject, resource abac.Resource, env abac.Environment) *risk.EvaluateResponse {
	if h.riskClient == nil {
		return nil
	}

	req := &risk.EvaluateRequest{
		RequestID: fmt.Sprintf("%d", time.Now().UnixNano()),
		Subject: risk.SubjectContext{
			ID:      subject.ID,
			Role:    subject.Role,
			Project: subject.Project,
		},
		Resource: risk.ResourceContext{
			Path:        resource.Path,
			Sensitivity: resource.Sensitivity,
		},
		Environment: risk.EnvironmentContext{
			Time: env.Time,
			IP:   env.IP,
		},
		Context: risk.RiskContext{
			IsWorkHours:     isWorkHours(),
			IsKnownLocation: false, // 简化：生产应查IP库
		},
	}

	resp, err := h.riskClient.Evaluate(ctx, req)
	if err != nil {
		logger.Warnf("Risk evaluation failed, falling back to ABAC: %v", err)
		return nil
	}
	return resp
}

func isWorkHours() bool {
	h := time.Now().Hour()
	return h >= 9 && h < 18
}
```

- [ ] **Step 2: 在 GetFile/PutFile 中调用风险评分**

在 `GetFile` 的 ABAC 评估通过之后（decision.Allowed == true 之后），添加风险评分调用。在 `PutFile` 的 ABAC 评估通过后同样添加。

在 `GetFile` 和 `PutFile` 中，ABAC 通过后、文件操作前，添加：

```go
// 风险评分（ABAC 通过后）
if h.riskClient != nil {
	riskResp := h.evaluateRisk(r.Context(), subject, resource, env)
	if riskResp != nil {
		switch riskResp.RiskAction() {
		case "deny":
			httputil.Error(w, http.StatusForbidden, "risk score too high: "+riskResp.Reason)
			return
		case "mfa":
			// 可选：触发 Step-up MFA（当前版本记录日志）
			logger.Infof("Risk MFA recommended for %s: score=%.2f", filePath, riskResp.RiskScore)
		case "approval":
			logger.Infof("Risk approval required for %s: score=%.2f", filePath, riskResp.RiskScore)
			// 待实现审批工作流
		}
		// 记录风险评分到审计事件
		event.Details = map[string]interface{}{
			"risk_score":      riskResp.RiskScore,
			"risk_level":      riskResp.RiskLevel,
			"risk_recommendation": riskResp.Recommendation,
		}
	}
}
```

- [ ] **Step 3: 在 gateway main.go 中初始化 riskClient**

修改 `cmd/gateway/main.go`，import 中添加 `"github.com/L1566/FileGuard/pkg/risk"`，在初始化 KMS 客户端之后添加：

```go
// 初始化 Risk 客户端
var riskClient *risk.Client
if cfg.Risk.Enabled {
	riskClient = risk.NewClient(cfg.Risk.ServiceURL, cfg.Risk.Timeout)
}
```

修改 `NewFileHandler` 调用，添加 `riskClient` 参数：

```go
fileHandler := handler.NewFileHandler(store, evaluator, auditLogger, kmsClient, dlpDetector, riskClient)
```

- [ ] **Step 4: 验证编译**

Run: `go build ./cmd/gateway/... ./internal/gateway/...`
Expected: 编译成功

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/handler/file.go cmd/gateway/main.go
git commit -m "feat(risk): integrate risk scoring into Gateway file handlers"
```

---

### Task 9: 集成测试

**Files:**
- Create: `test/integration/risk_test.go`

- [ ] **Step 1: 编写集成测试**

```go
package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/L1566/FileGuard/internal/riskservice/handler"
	"github.com/L1566/FileGuard/pkg/risk"
)

func TestRiskServiceEvaluate(t *testing.T) {
	scorer, err := risk.NewScorer(risk.ScorerConfig{
		Model:     "claude-sonnet-4-6",
		APIKeyEnv: "FILEGUARD_LLM_API_KEY",
		Timeout:   10000,
		CacheSize: 100,
		CacheTTL:  300,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := handler.NewHandler(scorer)
	req := httptest.NewRequest("POST", "/api/risk/evaluate", nil)
	req.Body = io.NopCloser(strings.NewReader(`{
		"request_id": "test-001",
		"subject": {"role": "engineer", "project": "ev_battery"},
		"resource": {"path": "/battery/test.xlsx", "sensitivity": "internal"},
		"environment": {"time": "2026-06-23T14:00:00+08:00", "ip": "10.0.0.1"},
		"context": {
			"recent_access_count_1h": 3,
			"unique_files_accessed_1h": 2,
			"is_work_hours": true,
			"is_known_location": true,
			"content_summary": "test battery parameters"
		}
	}`))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.Evaluate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp risk.EvaluateResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.RiskScore < 0 || resp.RiskScore > 1.0 {
		t.Errorf("risk_score out of range: %f", resp.RiskScore)
	}
	if resp.RiskLevel == "" {
		t.Error("risk_level should not be empty")
	}
	if resp.RequestID != "test-001" {
		t.Errorf("request_id = %s, want test-001", resp.RequestID)
	}
	t.Logf("Risk score: %.2f, level: %s, recommendation: %s",
		resp.RiskScore, resp.RiskLevel, resp.Recommendation)
}

func TestRiskServiceHealthCheck(t *testing.T) {
	scorer, _ := risk.NewScorer(risk.ScorerConfig{
		Model: "test", APIKeyEnv: "NONE",
		Timeout: 10000, CacheSize: 10, CacheTTL: 300,
	})
	h := handler.NewHandler(scorer)

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	h.HealthCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("health check returned %d", rec.Code)
	}
}

func TestRiskServiceEmptyAPIKey(t *testing.T) {
	// 无 API Key 时返回默认低风险（不报错）
	scorer, _ := risk.NewScorer(risk.ScorerConfig{
		Model: "claude-sonnet-4-6", APIKeyEnv: "NONEXISTENT_ENV_VAR",
		Timeout: 5000, CacheSize: 10, CacheTTL: 300,
	})

	resp, err := scorer.Evaluate(nil, &risk.EvaluateRequest{
		RequestID: "test",
		Subject:   risk.SubjectContext{Role: "guest"},
		Resource:  risk.ResourceContext{Path: "/test.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RiskScore != 0.1 || resp.Recommendation != "allow" {
		t.Errorf("expected default low-risk, got score=%.2f rec=%s", resp.RiskScore, resp.Recommendation)
	}
}
```

- [ ] **Step 2: 运行集成测试**

Run: `go test ./test/integration/ -v -run TestRiskService`
Expected: 全部 PASS（使用默认评分，不依赖真实 API Key）

- [ ] **Step 3: Commit**

```bash
git add test/integration/risk_test.go
git commit -m "test(risk): add Risk Service integration tests"
```

---

### Task 10: Makefile 更新 & 最终验证

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: 更新 Makefile**

在 `Makefile` 中添加 `run-riskservice` 和 `build` 目标更新：

```makefile
build:
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/gateway ./cmd/gateway
	go build -o $(BINARY_DIR)/policy ./cmd/policy
	go build -o $(BINARY_DIR)/audit ./cmd/audit
	go build -o $(BINARY_DIR)/kms ./cmd/kms
	go build -o $(BINARY_DIR)/agent ./cmd/agent
	go build -o $(BINARY_DIR)/riskservice ./cmd/riskservice

run-riskservice:
	go run ./cmd/riskservice -config configs/riskservice.yaml
```

- [ ] **Step 2: 全量构建验证**

Run: `go build ./...`
Expected: 全部包编译成功（含新增 riskservice）

- [ ] **Step 3: 全量测试验证**

Run: `go test -race -count=1 ./...`
Expected: 全部 PASS（单元测试 + 集成测试 + 已有测试）

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "chore: add riskservice build/run targets to Makefile"
```
