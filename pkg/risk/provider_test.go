package risk

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "plain json",
			raw:  `{"risk_score": 0.3, "risk_level": "low"}`,
			want: `{"risk_score": 0.3, "risk_level": "low"}`,
		},
		{
			name: "markdown code fence",
			raw:  "```json\n{\"risk_score\": 0.72}\n```",
			want: `{"risk_score": 0.72}`,
		},
		{
			name: "markdown code fence without lang",
			raw:  "```\n{\"risk_score\": 0.5}\n```",
			want: `{"risk_score": 0.5}`,
		},
		{
			name: "json wrapped in text",
			raw:  "Here is the result: {\"risk_score\": 0.1} thanks!",
			want: `{"risk_score": 0.1}`,
		},
		{
			name: "whitespace around json",
			raw:  "  \n{\"risk_score\": 0.9}\n  ",
			want: `{"risk_score": 0.9}`,
		},
		{
			name: "empty input",
			raw:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSON([]byte(tt.raw))
			if string(got) != tt.want {
				t.Errorf("extractJSON(%q) = %q, want %q", tt.raw, string(got), tt.want)
			}
		})
	}
}

func TestParseEvaluationJSON_HandlesMarkdown(t *testing.T) {
	// DeepSeek 常返回 markdown 包裹的 JSON
	raw := "```json\n{\"risk_score\": 0.72, \"risk_level\": \"high\", \"recommendation\": \"approval\", \"reason\": \"测试\"}\n```"
	result := parseEvaluationJSON([]byte(raw))

	if result.RiskScore != 0.72 {
		t.Errorf("RiskScore = %f, want 0.72", result.RiskScore)
	}
	if result.RiskLevel != "high" {
		t.Errorf("RiskLevel = %s, want high", result.RiskLevel)
	}
}

func TestParseEvaluationJSON_Clamping(t *testing.T) {
	// 验证钳位
	result := parseEvaluationJSON([]byte(`{"risk_score": 1.5, "risk_level": "critical"}`))
	if result.RiskScore != 1.0 {
		t.Errorf("RiskScore should be clamped to 1.0, got %f", result.RiskScore)
	}

	result = parseEvaluationJSON([]byte(`{"risk_score": -0.5, "risk_level": "low"}`))
	if result.RiskScore != 0.0 {
		t.Errorf("RiskScore should be clamped to 0.0, got %f", result.RiskScore)
	}
}

func TestParseEvaluationJSON_InvalidJSON(t *testing.T) {
	result := parseEvaluationJSON([]byte("not json at all"))
	if result.RiskScore != 0.1 {
		t.Error("should return default low-risk on parse failure")
	}
	if result.Recommendation != "allow" {
		t.Error("should default to allow")
	}
}

func TestParseEvaluationJSON_ValidJSON(t *testing.T) {
	input := `{"risk_score": 0.5, "risk_level": "medium", "recommendation": "mfa", "reason": "suspicious time", "factors": {"time_anomaly": 0.4}}`
	result := parseEvaluationJSON([]byte(input))

	if result.RiskScore != 0.5 {
		t.Errorf("RiskScore = %f, want 0.5", result.RiskScore)
	}
	if result.Recommendation != "mfa" {
		t.Errorf("Recommendation = %s, want mfa", result.Recommendation)
	}
	if result.Factors["time_anomaly"] != 0.4 {
		t.Errorf("Factors[time_anomaly] = %f, want 0.4", result.Factors["time_anomaly"])
	}
}
