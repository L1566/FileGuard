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
	degraded   bool
}

// ScorerConfig 评分器配置
type ScorerConfig struct {
	Model      string
	APIKeyEnv  string
	Timeout    time.Duration
	MaxRetries int
	CacheSize  int
	CacheTTL   time.Duration
}

// NewScorer 创建评分引擎
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
	// 脱敏
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

	// 成功后重置
	s.failCount.Store(0)
	s.mu.Lock()
	s.degraded = false
	s.mu.Unlock()

	resp.LatencyMs = time.Since(start).Milliseconds()
	resp.Model = s.model

	// 写缓存
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
		logger.Warnf("Failed to parse LLM JSON response, using defaults: %v", err)
		return result, nil
	}

	// 钳位
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
