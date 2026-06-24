package risk

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/L1566/FileGuard/pkg/logger"
)

// =============================================================================
// Provider 接口 — 抽象各 AI 厂商的 API 差异
// =============================================================================

// Provider 封装 LLM 提供商的端点、认证、请求/响应格式
type Provider interface {
	Name() string
	BuildRequest(systemPrompt, userPrompt, model string) ([]byte, error)
	ParseResponse(body []byte) (*EvaluateResponse, error)
	Endpoint() string
	AuthHeader(apiKey string) (key, value string)
	ExtraHeaders() map[string]string
	RequiresAPIKey() bool // 是否需要 API Key（本地部署返回 false）
}

// =============================================================================
// 默认端点表
// =============================================================================

type providerDefaults struct {
	Endpoint  string
	KeyPrefix string // 用于友好警告（可选）
}

var defaultEndpoints = map[string]providerDefaults{
	"anthropic": {
		Endpoint:  "https://api.anthropic.com/v1/messages",
		KeyPrefix: "sk-ant-",
	},
	"openai": {
		Endpoint:  "https://api.openai.com/v1/chat/completions",
		KeyPrefix: "sk-",
	},
	"deepseek": {
		Endpoint:  "https://api.deepseek.com/chat/completions",
		KeyPrefix: "sk-",
	},
	"google": {
		Endpoint:  "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
		KeyPrefix: "",
	},
	"groq": {
		Endpoint:  "https://api.groq.com/openai/v1/chat/completions",
		KeyPrefix: "gsk_",
	},
	"llamacpp": {
		Endpoint:  "http://127.0.0.1:8080/v1/chat/completions",
		KeyPrefix: "",
	},
	"ollama": {
		Endpoint:  "http://127.0.0.1:11434/v1/chat/completions",
		KeyPrefix: "",
	},
}

// SupportedProviders 返回所有支持的 provider 名称列表
func SupportedProviders() []string {
	names := make([]string, 0, len(defaultEndpoints))
	for k := range defaultEndpoints {
		names = append(names, k)
	}
	return names
}

// =============================================================================
// 工厂函数
// =============================================================================

// NewProvider 根据名称创建 Provider。endpoint 非空时覆盖内置默认值。
func NewProvider(name, model, endpoint string) (Provider, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	defaults, ok := defaultEndpoints[name]
	if !ok {
		return nil, fmt.Errorf("risk: unknown provider %q (supported: %s)", name, strings.Join(SupportedProviders(), ", "))
	}

	ep := defaults.Endpoint
	if endpoint != "" {
		ep = endpoint
	}

	switch name {
	case "anthropic":
		return &AnthropicProvider{
			name:     name,
			model:    model,
			endpoint: ep,
		}, nil

	case "openai", "deepseek", "groq":
		return &OpenAICompatibleProvider{
			name:     name,
			model:    model,
			endpoint: ep,
		}, nil

	case "llamacpp", "ollama":
		return &OpenAICompatibleProvider{
			name:     name,
			model:    model,
			endpoint: ep,
			noAuth:   true,
		}, nil

	case "google":
		ep = strings.ReplaceAll(ep, "{model}", model)
		return &GoogleProvider{
			name:     name,
			model:    model,
			endpoint: ep,
		}, nil

	default:
		return nil, fmt.Errorf("risk: unimplemented provider %q", name)
	}
}

// =============================================================================
// 共享 — LLM 返回的 JSON 文本 → EvaluateResponse
// =============================================================================

// parseEvaluationJSON 解析 LLM 返回的 JSON 文本为 EvaluateResponse，
// 钳位 risk_score 到 [0, 1]，解析失败时返回安全默认值。
// 自动处理 LLM 常见的 JSON 包裹格式（markdown 代码块、前后空白）。
func parseEvaluationJSON(text []byte) *EvaluateResponse {
	result := &EvaluateResponse{
		RiskScore:      0.1,
		RiskLevel:      "low",
		Recommendation: "allow",
		Reason:         "default (LLM parse fallback)",
	}

	cleaned := extractJSON(text)
	if err := json.Unmarshal(cleaned, result); err != nil {
		logger.Warnf("Failed to parse LLM JSON response, using defaults: %v\n  raw (first 200 chars): %.200s", err, string(text))
		return result
	}
	if result.RiskScore < 0 {
		result.RiskScore = 0
	}
	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	}
	return result
}

// extractJSON 从 LLM 响应文本中提取 JSON 片段。
// 处理常见情况：markdown 代码块包裹、前后多余文本/空白。
func extractJSON(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))

	// 情况 1: ```json ... ``` 或 ``` ... ```
	if idx := strings.Index(s, "```"); idx >= 0 {
		start := strings.Index(s[idx:], "\n")
		if start < 0 {
			start = 3
		} else {
			start = idx + start + 1
		}
		end := strings.Index(s[start:], "```")
		if end >= 0 {
			return []byte(strings.TrimSpace(s[start : start+end]))
		}
		return []byte(strings.TrimSpace(s[start:]))
	}

	// 情况 2: 找到第一个 { 到最后一个 }
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return []byte(s[start : end+1])
	}

	return []byte(s)
}
