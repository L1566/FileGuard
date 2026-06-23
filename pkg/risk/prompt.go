package risk

import (
	"bytes"
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

请返回 JSON: {"risk_score": <0.0-1.0>, "risk_level": "<low|medium|high|critical>", "factors": {"time_anomaly": ..., "location_anomaly": ..., "behavior_volume": ..., "content_sensitivity": ...}, "recommendation": "<allow|mfa|approval|deny>", "reason": "<简短中文解释>"}`))

// BuildPrompt 构造 LLM 请求的 system + user messages（Provider 无关）
func BuildPrompt(req *EvaluateRequest) (system, user string, err error) {
	var buf bytes.Buffer
	if err := userPromptTmpl.Execute(&buf, req); err != nil {
		return "", "", fmt.Errorf("prompt render: %w", err)
	}
	return systemPrompt, buf.String(), nil
}

