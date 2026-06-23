package risk

import (
	"encoding/json"
	"fmt"
)

// OpenAICompatibleProvider 兼容 OpenAI Chat Completions API 格式的提供商
// 适用于：OpenAI ChatGPT、DeepSeek、Groq 等任何遵循 /v1/chat/completions 的 API
type OpenAICompatibleProvider struct {
	name     string
	model    string
	endpoint string
}

func (p *OpenAICompatibleProvider) Name() string { return p.name }

func (p *OpenAICompatibleProvider) BuildRequest(systemPrompt, userPrompt, model string) ([]byte, error) {
	body := map[string]interface{}{
		"model":       model,
		"max_tokens":  1024,
		"temperature": 0.0,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
	}

	// DeepSeek V4 推理模型默认启用 thinking，会消耗 max_tokens 配额导致 JSON 输出被截断。
	// 风险评分是简单分类任务，显式禁用 thinking。该字段对其他兼容提供商无副作用。
	if p.name == "deepseek" {
		body["thinking"] = map[string]string{"type": "disabled"}
	}

	return json.Marshal(body)
}

func (p *OpenAICompatibleProvider) ParseResponse(body []byte) (*EvaluateResponse, error) {
	var llmResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &llmResp); err != nil {
		return nil, fmt.Errorf("risk: parse %s response: %w", p.name, err)
	}
	if len(llmResp.Choices) == 0 {
		return nil, fmt.Errorf("risk: %s returned empty choices", p.name)
	}
	return parseEvaluationJSON([]byte(llmResp.Choices[0].Message.Content)), nil
}

func (p *OpenAICompatibleProvider) Endpoint() string { return p.endpoint }

func (p *OpenAICompatibleProvider) AuthHeader(apiKey string) (string, string) {
	return "Authorization", "Bearer " + apiKey
}

func (p *OpenAICompatibleProvider) ExtraHeaders() map[string]string { return nil }
