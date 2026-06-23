package risk

import (
	"encoding/json"
	"fmt"
)

// GoogleProvider Google Gemini API 实现
type GoogleProvider struct {
	name     string
	model    string
	endpoint string
}

func (p *GoogleProvider) Name() string { return p.name }

func (p *GoogleProvider) BuildRequest(systemPrompt, userPrompt, model string) ([]byte, error) {
	body := map[string]interface{}{
		"system_instruction": map[string]interface{}{
			"parts": []map[string]string{{"text": systemPrompt}},
		},
		"contents": []map[string]interface{}{
			{
				"role": "user",
				"parts": []map[string]string{{"text": userPrompt}},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0.0,
			"maxOutputTokens": 256,
		},
	}
	return json.Marshal(body)
}

func (p *GoogleProvider) ParseResponse(body []byte) (*EvaluateResponse, error) {
	var llmResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &llmResp); err != nil {
		return nil, fmt.Errorf("risk: parse google response: %w", err)
	}
	if len(llmResp.Candidates) == 0 {
		return nil, fmt.Errorf("risk: google returned empty candidates")
	}
	parts := llmResp.Candidates[0].Content.Parts
	if len(parts) == 0 {
		return nil, fmt.Errorf("risk: google returned empty content parts")
	}
	return parseEvaluationJSON([]byte(parts[0].Text)), nil
}

func (p *GoogleProvider) Endpoint() string { return p.endpoint }

func (p *GoogleProvider) AuthHeader(apiKey string) (string, string) {
	return "x-goog-api-key", apiKey
}

func (p *GoogleProvider) ExtraHeaders() map[string]string { return nil }
