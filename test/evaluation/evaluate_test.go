package evaluation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/L1566/FileGuard/pkg/risk"
)

// TestCase JSON 测试用例结构
type TestCase struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Desc            string  `json:"desc"`
	Input           Input   `json:"input"`
	ExpectedLevel   string  `json:"expected_level"`
	ExpectedAction  string  `json:"expected_action"`
	ExpectedRange   [2]int  `json:"expected_score_range"`
}

// Input 测试输入（对应 ScoreInput）
type Input struct {
	IsWorkHours   bool   `json:"is_work_hours"`
	IsDeepNight   bool   `json:"is_deep_night"`
	IPRiskLevel   string `json:"ip_risk_level"`
	DeviceTrust   string `json:"device_trust"`
	HourlyAccess  int    `json:"hourly_access"`
	UniqueFiles1H int    `json:"unique_files_1h"`
}

// EvalResult 单条评估结果
type EvalResult struct {
	CaseID         string
	Name           string
	Desc           string
	ExpectedLevel  string
	ExpectedAction string
	ActualScore    float64
	ActualLevel    string
	ActualAction   string
	Reason         string
	Factors        map[string]float64
	LevelMatch     bool
	ActionMatch    bool
	InRange        bool
}

// loadTestCases 从 JSON 文件加载测试用例
func loadTestCases(t *testing.T) []TestCase {
	t.Helper()
	path := filepath.Join("test_cases.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("无法读取测试用例文件 %s: %v", path, err)
	}
	var cases []TestCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("解析测试用例失败: %v", err)
	}
	return cases
}

// runCase 执行单条测试用例
func runCase(tc TestCase) EvalResult {
	rs := risk.NewRuleScorer()
	resp := rs.Score(risk.ScoreInput{
		IsWorkHours:   tc.Input.IsWorkHours,
		IsDeepNight:   tc.Input.IsDeepNight,
		IPRiskLevel:   tc.Input.IPRiskLevel,
		DeviceTrust:   tc.Input.DeviceTrust,
		HourlyAccess:  tc.Input.HourlyAccess,
		UniqueFiles1H: tc.Input.UniqueFiles1H,
	})

	total := int(resp.RiskScore * 100)
	inRange := total >= tc.ExpectedRange[0] && total <= tc.ExpectedRange[1]

	return EvalResult{
		CaseID:         tc.ID,
		Name:           tc.Name,
		Desc:           tc.Desc,
		ExpectedLevel:  tc.ExpectedLevel,
		ExpectedAction: tc.ExpectedAction,
		ActualScore:    resp.RiskScore,
		ActualLevel:    resp.RiskLevel,
		ActualAction:   resp.Recommendation,
		Reason:         resp.Reason,
		Factors:        resp.Factors,
		LevelMatch:     resp.RiskLevel == tc.ExpectedLevel,
		ActionMatch:    resp.Recommendation == tc.ExpectedAction,
		InRange:        inRange,
	}
}

// =============================================================================
// 评估主入口
// =============================================================================

func TestEvaluation(t *testing.T) {
	cases := loadTestCases(t)
	if len(cases) == 0 {
		t.Fatal("测试用例为空")
	}

	// 执行所有用例
	results := make([]EvalResult, 0, len(cases))
	for _, tc := range cases {
		results = append(results, runCase(tc))
	}

	// 统计
	levelMatchCount := 0
	actionMatchCount := 0
	rangeMatchCount := 0
	for _, r := range results {
		if r.LevelMatch {
			levelMatchCount++
		}
		if r.ActionMatch {
			actionMatchCount++
		}
		if r.InRange {
			rangeMatchCount++
		}
	}
	total := len(results)

	// =========================================================================
	// 输出 Markdown 报告
	// =========================================================================
	var sb strings.Builder

	sb.WriteString("# FileGuard AI 风险评分 — 确定性规则评估报告\n\n")
	sb.WriteString(fmt.Sprintf("**评估引擎**: RuleScorer（确定性加权规则，不依赖 LLM）  \n"))
	sb.WriteString(fmt.Sprintf("**测试用例数**: %d  \n", total))
	sb.WriteString(fmt.Sprintf("**评分公式**: `总分 = (非工作时间×20%% + IP风险×30%% + 设备信任×25%% + 批量行为×25%%) / 100`  \n\n"))

	// 汇总
	sb.WriteString("## 一、汇总统计\n\n")
	sb.WriteString("| 指标 | 通过 | 总数 | 通过率 |\n")
	sb.WriteString("|------|:----:|:----:|:------:|\n")
	sb.WriteString(fmt.Sprintf("| 风险等级匹配 | %d | %d | %.1f%% |\n",
		levelMatchCount, total, float64(levelMatchCount)/float64(total)*100))
	sb.WriteString(fmt.Sprintf("| 建议动作匹配 | %d | %d | %.1f%% |\n",
		actionMatchCount, total, float64(actionMatchCount)/float64(total)*100))
	sb.WriteString(fmt.Sprintf("| 分数区间匹配 | %d | %d | %.1f%% |\n",
		rangeMatchCount, total, float64(rangeMatchCount)/float64(total)*100))
	sb.WriteString("\n")

	// 分段分布
	greenCount := 0
	yellowCount := 0
	redCount := 0
	for _, r := range results {
		s := int(r.ActualScore * 100)
		if s <= 30 {
			greenCount++
		} else if s <= 70 {
			yellowCount++
		} else {
			redCount++
		}
	}
	sb.WriteString("### 评分分段分布\n\n")
	sb.WriteString("| 分段 | 分数区间 | 用例数 | 占比 |\n")
	sb.WriteString("|------|:--------:|:------:|:----:|\n")
	sb.WriteString(fmt.Sprintf("| 🟢 绿色通道 (allow) | 0–30 | %d | %.0f%% |\n",
		greenCount, float64(greenCount)/float64(total)*100))
	sb.WriteString(fmt.Sprintf("| 🟡 黄色预警 (mfa) | 31–70 | %d | %.0f%% |\n",
		yellowCount, float64(yellowCount)/float64(total)*100))
	sb.WriteString(fmt.Sprintf("| 🔴 红色拦截 (deny) | 71–100 | %d | %.0f%% |\n",
		redCount, float64(redCount)/float64(total)*100))
	sb.WriteString("\n")

	// =========================================================================
	// 详细结果表
	// =========================================================================
	sb.WriteString("## 二、逐用例详细结果\n\n")
	sb.WriteString("| ID | 场景 | 预期等级 | 预期动作 | 评分 | 实际等级 | 实际动作 | 等级 | 动作 |\n")
	sb.WriteString("|----|------|----------|----------|:----:|----------|----------|:----:|:----:|\n")
	for _, r := range results {
		levelIcon := "✅"
		if !r.LevelMatch {
			levelIcon = "❌"
		}
		actionIcon := "✅"
		if !r.ActionMatch {
			actionIcon = "❌"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %.0f | %s | %s | %s | %s |\n",
			r.CaseID, r.Name,
			r.ExpectedLevel, r.ExpectedAction,
			r.ActualScore*100,
			r.ActualLevel, r.ActualAction,
			levelIcon, actionIcon))
	}
	sb.WriteString("\n")

	// =========================================================================
	// 不匹配分析
	// =========================================================================
	mismatches := make([]EvalResult, 0)
	for _, r := range results {
		if !r.LevelMatch || !r.ActionMatch {
			mismatches = append(mismatches, r)
		}
	}
	if len(mismatches) > 0 {
		sb.WriteString("## 三、不匹配用例分析\n\n")
		for _, r := range mismatches {
			sb.WriteString(fmt.Sprintf("### %s — %s\n\n", r.CaseID, r.Name))
			sb.WriteString(fmt.Sprintf("**场景**: %s\n\n", r.Desc))
			sb.WriteString(fmt.Sprintf("- 预期: `%s` / `%s`\n", r.ExpectedLevel, r.ExpectedAction))
			sb.WriteString(fmt.Sprintf("- 实际: `%s` / `%s` (score=%.0f)\n", r.ActualLevel, r.ActualAction, r.ActualScore*100))
			sb.WriteString(fmt.Sprintf("- 原因: %s\n\n", r.Reason))

			// 各因子贡献
			sb.WriteString("**因子分解**:\n\n")
			sb.WriteString("| 因子 | 分值 |\n")
			sb.WriteString("|------|:----:|\n")
			for k, v := range r.Factors {
				sb.WriteString(fmt.Sprintf("| %s | %.2f |\n", k, v))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("## 三、不匹配用例分析\n\n✅ 所有用例的等级和动作均与预期一致。\n\n")
	}

	// =========================================================================
	// 因子贡献分析
	// =========================================================================
	sb.WriteString("## 四、风险因子贡献分析\n\n")

	// 按因子分组统计平均分
	factorScores := map[string][]float64{
		"时间异常":   {},
		"位置异常":   {},
		"设备信任":   {},
		"行为量异常": {},
	}
	for _, r := range results {
		factorScores["时间异常"] = append(factorScores["时间异常"], r.Factors["time_anomaly"])
		factorScores["位置异常"] = append(factorScores["位置异常"], r.Factors["location_anomaly"])
		factorScores["设备信任"] = append(factorScores["设备信任"], r.Factors["device_trust"])
		factorScores["行为量异常"] = append(factorScores["行为量异常"], r.Factors["behavior_volume"])
	}

	sb.WriteString("| 因子 | 权重 | 平均分 | 最高分 | 最低分 | 说明 |\n")
	sb.WriteString("|------|:----:|:------:|:------:|:------:|------|\n")
	for name, weight := range map[string]int{"时间异常": 20, "位置异常": 30, "设备信任": 25, "行为量异常": 25} {
		scores := factorScores[name]
		avg, min, max := stats(scores)
		sb.WriteString(fmt.Sprintf("| %s | %d%% | %.2f | %.2f | %.2f | ",
			name, weight, avg, max, min))

		// 因子含义说明
		switch name {
		case "时间异常":
			sb.WriteString("非工作时间(+50)/凌晨(+100)")
		case "位置异常":
			sb.WriteString("国内(+50)/境外(+100)")
		case "设备信任":
			sb.WriteString("个人设备(+50)/未注册(+100)")
		case "行为量异常":
			sb.WriteString("中量(+50)/批量(+100)")
		}
		sb.WriteString(" |\n")
	}
	sb.WriteString("\n")

	// =========================================================================
	// 边界行为分析
	// =========================================================================
	sb.WriteString("## 五、边界行为分析\n\n")
	sb.WriteString("验证分段阈值附近的评分稳定性：\n\n")

	// 挑出接近边界的用例
	boundaryCases := []struct {
		name     string
		score    int
		boundary string
	}{}
	for _, r := range results {
		s := int(r.ActualScore * 100)
		if s <= 30 && s >= 20 {
			boundaryCases = append(boundaryCases, struct {
				name     string
				score    int
				boundary string
			}{r.Name, s, "绿色上界(30)"})
		}
		if s >= 31 && s <= 45 {
			boundaryCases = append(boundaryCases, struct {
				name     string
				score    int
				boundary string
			}{r.Name, s, "黄色下界(31)"})
		}
		if s >= 60 && s <= 75 {
			boundaryCases = append(boundaryCases, struct {
				name     string
				score    int
				boundary string
			}{r.Name, s, "黄红交界(70-71)"})
		}
	}
	sort.Slice(boundaryCases, func(i, j int) bool {
		return boundaryCases[i].score < boundaryCases[j].score
	})

	sb.WriteString("| 边界 | 场景 | 评分 | 等级 | 动作 |\n")
	sb.WriteString("|------|------|:----:|------|------|\n")
	for _, bc := range boundaryCases {
		// find result
		for _, r := range results {
			if r.Name == bc.name {
				sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n",
					bc.boundary, bc.name, bc.score, r.ActualLevel, r.ActualAction))
				break
			}
		}
	}
	sb.WriteString("\n")

	// =========================================================================
	// 局限性
	// =========================================================================
	sb.WriteString("## 六、规则评分局限性\n\n")
	sb.WriteString("确定性规则评分的已知局限：\n\n")
	sb.WriteString("1. **线性加权无法捕捉非线性交互**: 例如\"凌晨+境外+未注册设备\" vs \"凌晨+境外+公司设备\"，前者理应远超后者的风险，但线性模型的增量是固定的\n")
	sb.WriteString("2. **缺乏内容语义理解**: 规则评分不分析文件内容（`content_summary` 字段在此模式下未使用），无法识别\"电池配方\"比\"会议纪要\"更敏感\n")
	sb.WriteString("3. **阈值固定**: 分段阈值（30/70）是硬编码的，无法根据企业风险偏好动态调整\n")
	sb.WriteString("4. **缺少行为序列上下文**: 无法分析\"过去7天从未访问，突然批量下载\"这类时间序列模式\n\n")
	sb.WriteString("> 这些局限性正是引入 LLM 风险评分的动机。建议在后续评估中对比 LLM 评分与规则评分在相同场景下的差异，特别是关注规则评分\"漏判\"（高危场景打低分）和\"误判\"（正常场景打高分）的案例。\n\n")

	// =========================================================================
	// 结论
	// =========================================================================
	sb.WriteString("## 七、结论\n\n")
	accuracy := float64(actionMatchCount) / float64(total) * 100
	sb.WriteString(fmt.Sprintf("- **动作准确率**: %.1f%% (%d/%d)\n", accuracy, actionMatchCount, total))
	sb.WriteString(fmt.Sprintf("- **等级准确率**: %.1f%% (%d/%d)\n", float64(levelMatchCount)/float64(total)*100, levelMatchCount, total))
	sb.WriteString(fmt.Sprintf("- **区间命中率**: %.1f%% (%d/%d)\n", float64(rangeMatchCount)/float64(total)*100, rangeMatchCount, total))
	sb.WriteString("\n")

	if accuracy == 100 {
		sb.WriteString("确定性规则评分在所有测试用例上动作预测完全正确，说明评分公式和分段逻辑实现无误，可以作为 LLM 风险评分的可靠 fallback 基线。\n")
	} else {
		sb.WriteString(fmt.Sprintf("存在 %d 个不匹配用例，详见第三章节的分析。\n", len(mismatches)))
	}

	// =========================================================================
	// 写入文件 + 控制台断言
	// =========================================================================

	// 写入报告文件
	reportPath := filepath.Join("..", "..", "docs", "AI风险评分评估报告.md")
	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		t.Errorf("写入报告文件失败: %v", err)
	}
	t.Logf("评估报告已写入: %s", reportPath)

	// 控制台断言
	t.Logf("\n%s", sb.String())

	if levelMatchCount != total {
		t.Errorf("等级匹配: %d/%d (%.1f%%)", levelMatchCount, total, float64(levelMatchCount)/float64(total)*100)
	}
	if actionMatchCount != total {
		t.Errorf("动作匹配: %d/%d (%.1f%%)", actionMatchCount, total, float64(actionMatchCount)/float64(total)*100)
	}
}

// stats 计算均值、最小值、最大值
func stats(scores []float64) (avg, min, max float64) {
	if len(scores) == 0 {
		return 0, 0, 0
	}
	min = scores[0]
	max = scores[0]
	sum := 0.0
	for _, s := range scores {
		sum += s
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
	}
	return sum / float64(len(scores)), min, max
}
