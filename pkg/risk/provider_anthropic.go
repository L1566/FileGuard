package risk

import (
	"encoding/json"
	"fmt"
)

// AnthropicProvider Claude Messages API 实现
type AnthropicProvider struct {
	name     string
	model    string
	endpoint string
}

func (p *AnthropicProvider) Name() string { return p.name }

func (p *AnthropicProvider) BuildRequest(systemPrompt, userPrompt, model string) ([]byte, error) {
	body := map[string]interface{}{
		"model":       model,
		"max_tokens":  256,
		"temperature": 0.0,
		"system":      systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userPrompt},
		},
	}
	return json.Marshal(body)
}

func (p *AnthropicProvider) ParseResponse(body []byte) (*EvaluateResponse, error) {
	var llmResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &llmResp); err != nil {
		return nil, fmt.Errorf("risk: parse anthropic response: %w", err)
	}
	if len(llmResp.Content) == 0 {
		return nil, fmt.Errorf("risk: anthropic returned empty content")
	}
	return parseEvaluationJSON([]byte(llmResp.Content[0].Text)), nil
}

func (p *AnthropicProvider) Endpoint() string { return p.endpoint }

func (p *AnthropicProvider) AuthHeader(apiKey string) (string, string) {
	return "x-api-key", apiKey
}

func (p *AnthropicProvider) ExtraHeaders() map[string]string {
	return map[string]string{"anthropic-version": "2023-06-01"}
}
