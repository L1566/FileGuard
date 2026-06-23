package risk

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	provider   Provider
	httpClient *http.Client
	cache      *lru.Cache[string, *EvaluateResponse]
	ttl        time.Duration
	failCount  atomic.Int32
	mu         sync.RWMutex
	degraded   bool
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
		model:    cfg.Model,
		apiKey:   apiKey,
		provider: p,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		cache: cache,
		ttl:   cfg.CacheTTL,
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

func (s *Scorer) callLLM(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	if s.apiKey == "" {
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.provider.Endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	key, value := s.provider.AuthHeader(s.apiKey)
	httpReq.Header.Set(key, value)

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

	return s.provider.ParseResponse(bodyBytes)
}

func (s *Scorer) defaultResponse() *EvaluateResponse {
	return &EvaluateResponse{
		RiskScore:      0.1,
		RiskLevel:      "low",
		Recommendation: "allow",
		Reason:         "risk service default (LLM unavailable)",
	}
}
