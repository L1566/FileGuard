package risk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/L1566/FileGuard/pkg/logger"
)

// Scorer 风险评分引擎
type Scorer struct {
	model        string
	apiKey       string
	provider     Provider
	ruleScorer   *RuleScorer
	httpClient   *http.Client
	cache        *lru.Cache[string, *EvaluateResponse]
	ttl          time.Duration
	ipClassifier *IPClassifier
	failCount    atomic.Int32
	mu           sync.RWMutex
	degraded     bool
	maxRetries   int // LLM 调用失败后的重试次数
}

// ScorerConfig 评分器配置
type ScorerConfig struct {
	Provider   Provider
	Model      string
	APIKeyEnv  string
	Timeout    time.Duration
	MaxRetries int
	CacheSize  int
	CacheTTL   time.Duration
}

// NewScorer 创建评分引擎。Provider 为 nil 时默认使用 Anthropic。
func NewScorer(cfg ScorerConfig) (*Scorer, error) {
	cache, err := lru.New[string, *EvaluateResponse](cfg.CacheSize)
	if err != nil {
		return nil, err
	}

	p := cfg.Provider
	if p == nil {
		p, err = NewProvider("anthropic", cfg.Model, "")
		if err != nil {
			return nil, err
		}
	}

	apiKey := os.Getenv(cfg.APIKeyEnv)
	if apiKey == "" {
		logger.Warnf("LLM API key env %s not set, risk scoring will use defaults (provider: %s)", cfg.APIKeyEnv, p.Name())
	}

	return &Scorer{
		model:        cfg.Model,
		apiKey:       apiKey,
		provider:     p,
		ruleScorer:   NewRuleScorer(),
		ipClassifier: NewIPClassifier(nil),
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache:      cache,
		ttl:        cfg.CacheTTL,
		maxRetries: cfg.MaxRetries,
	}, nil
}

// Evaluate 执行风险评分（优先返回缓存）
func (s *Scorer) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	req.Context.ContentSummary = Sanitize(req.Context.ContentSummary)

	cacheKey := s.cacheKey(req)
	if cached, ok := s.cache.Get(cacheKey); ok {
		cached.Cached = true
		return cached, nil
	}

	// 降级模式下跳过 LLM 调用，直接使用确定性规则评分
	if s.IsDegraded() {
		return s.fallbackResponse(req), nil
	}

	start := time.Now()
	resp, err := s.callLLM(req)
	if err != nil {
		logger.Warnf("LLM call failed (provider: %s): %v", s.provider.Name(), err)
		s.failCount.Add(1)
		if s.failCount.Load() >= 3 {
			s.mu.Lock()
			s.degraded = true
			s.mu.Unlock()
			logger.Errorf("Risk scorer degraded: %d consecutive failures", s.failCount.Load())
		}
		return s.fallbackResponse(req), nil
	}

	s.failCount.Store(0)
	s.mu.Lock()
	s.degraded = false
	s.mu.Unlock()

	resp.LatencyMs = time.Since(start).Milliseconds()
	resp.Model = s.model

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

// callLLM 调用 LLM 执行风险评分（含重试）。
// 使用独立的 Background context，不被调用方 HTTP 请求的 deadline 截断——
// LLM 超时由 httpClient.Timeout 独立控制。
func (s *Scorer) callLLM(req *EvaluateRequest) (*EvaluateResponse, error) {
	if s.provider.RequiresAPIKey() && s.apiKey == "" {
		return s.defaultResponse(), nil
	}

	system, user, err := BuildPrompt(req)
	if err != nil {
		return nil, err
	}

	body, err := s.provider.BuildRequest(system, user, s.model)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	maxAttempts := s.maxRetries + 1 // maxRetries=2 → 最多 3 次尝试
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		result, err := s.tryLLMCall(body)
		if err == nil {
			return result, nil
		}
		lastErr = err

		// 不可重试的错误（4xx、解析失败）直接退出
		if !isRetryable(err) {
			break
		}

		// 可重试的错误（网络超时/拒绝、5xx），短暂退避后重试
		if attempt < maxAttempts-1 {
			delay := time.Duration(attempt+1) * 500 * time.Millisecond
			logger.Debugf("LLM retry %d/%d after %v: %v", attempt+1, s.maxRetries, delay, err)
			time.Sleep(delay)
		}
	}

	return nil, fmt.Errorf("llm call failed after %d attempts: %w", maxAttempts, lastErr)
}

// tryLLMCall 执行单次 LLM HTTP 请求（使用独立 context）
func (s *Scorer) tryLLMCall(body []byte) (*EvaluateResponse, error) {
	httpReq, err := http.NewRequestWithContext(
		context.Background(), "POST", s.provider.Endpoint(), bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	key, value := s.provider.AuthHeader(s.apiKey)
	if key != "" {
		httpReq.Header.Set(key, value)
	}

	for k, v := range s.provider.ExtraHeaders() {
		httpReq.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("llm API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read llm response: %w", err)
	}

	logger.Debugf("LLM raw response (first 500 chars): %.500s", string(bodyBytes))

	return s.provider.ParseResponse(bodyBytes)
}

// isRetryable 判断 LLM 调用错误是否可重试。
// 网络/传输错误和 HTTP 5xx → 可重试；HTTP 4xx 和解析错误 → 不可重试。
func isRetryable(err error) bool {
	s := err.Error()
	// "llm call:" 前缀 = 网络/传输层错误
	if strings.Contains(s, "llm call:") {
		return true
	}
	// "llm API error 5" = HTTP 5xx 服务端错误
	if strings.Contains(s, "llm API error 5") {
		return true
	}
	return false
}

func (s *Scorer) defaultResponse() *EvaluateResponse {
	return &EvaluateResponse{
		RiskScore:      0.1,
		RiskLevel:      "low",
		Recommendation: "allow",
		Reason:         "risk service default (LLM unavailable)",
	}
}

// fallbackResponse LLM 不可用时回退到确定性规则评分
func (s *Scorer) fallbackResponse(req *EvaluateRequest) *EvaluateResponse {
	ipLevel := "foreign"
	if s.ipClassifier != nil {
		ipLevel, _ = s.ipClassifier.Classify(req.Environment.IP)
	}
	deviceTrust := "unregistered"
	if req.Context.IsTrustedDevice {
		deviceTrust = "corporate"
	}
	resp := s.ruleScorer.Score(ScoreInput{
		IsWorkHours:   req.Context.IsWorkHours,
		IsDeepNight:   isDeepNight(),
		IPRiskLevel:   ipLevel,
		DeviceTrust:   deviceTrust,
		HourlyAccess:  req.Context.RecentAccessCount1H,
		UniqueFiles1H: req.Context.UniqueFilesAccessed1H,
	})
	resp.Reason = "[rule fallback] " + resp.Reason
	return resp
}

func isDeepNight() bool {
	h := time.Now().Hour()
	return h >= 0 && h < 6
}

