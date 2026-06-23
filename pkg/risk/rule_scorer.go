package risk

import (
	"fmt"
)

// =============================================================================
// 确定性规则评分引擎 — 按选题.md 的加权公式实现
// =============================================================================

// RuleScorer 确定性加权风险评分器，不依赖 LLM
type RuleScorer struct{}

// NewRuleScorer 创建规则评分器
func NewRuleScorer() *RuleScorer {
	return &RuleScorer{}
}

// ScoreInput 评分输入（由 Gateway 采集的实际数据填充）
type ScoreInput struct {
	IsWorkHours   bool   // 是否工作时间
	IsDeepNight   bool   // 是否凌晨 (0:00-6:00)
	IPRiskLevel   string // intranet / domestic / foreign
	DeviceTrust   string // corporate / personal / unregistered
	HourlyAccess  int    // 最近1小时访问次数
	UniqueFiles1H int    // 最近1小时访问的唯一文件数
}

// Score 执行确定性加权评分，返回 EvaluateResponse。
// 公式: 总分 = Σ(因子分 × 权重%)/100，范围 0~100，按选题分段映射到动作
func (r *RuleScorer) Score(in ScoreInput) *EvaluateResponse {
	offHoursScore := r.scoreOffHours(in.IsWorkHours, in.IsDeepNight)
	ipScore := r.scoreIP(in.IPRiskLevel)
	deviceScore := r.scoreDevice(in.DeviceTrust)
	bulkScore := r.scoreBulkExport(in.HourlyAccess)

	// 加权总分 (0~100): Σ(score × weight%) / 100
	total := (offHoursScore*20 + ipScore*30 + deviceScore*25 + bulkScore*25) / 100

	level, action := r.segment(total)

	return &EvaluateResponse{
		RiskScore: float64(total) / 100.0,
		RiskLevel: level,
		Factors: map[string]float64{
			"time_anomaly":       float64(offHoursScore) / 100.0,
			"location_anomaly":   float64(ipScore) / 100.0,
			"device_trust":       float64(deviceScore) / 100.0,
			"behavior_volume":    float64(bulkScore) / 100.0,
		},
		Recommendation: action,
		Reason: fmt.Sprintf("rule-based: off_hours=%d ip=%d device=%d bulk=%d → total=%d",
			offHoursScore, ipScore, deviceScore, bulkScore, total),
		Model: "rule-scorer",
	}
}

// scoreOffHours 非工作时间评分
// 工作日 9:00-18:00 → 0 分；晚上 20:00 后 → 50 分；凌晨 0:00-6:00 → 100 分
// deepNight 由调用方根据当前时间判断
func (r *RuleScorer) scoreOffHours(isWorkHours, deepNight bool) int {
	if isWorkHours {
		return 0
	}
	if deepNight {
		return 100 // 凌晨 0:00-6:00
	}
	return 50 // 晚上/其他非工作时间
}

// scoreIP IP 因子评分
func (r *RuleScorer) scoreIP(level string) int {
	switch level {
	case "intranet":
		return 0
	case "domestic":
		return 50
	default:
		return 100
	}
}

// scoreDevice 设备信任评分
func (r *RuleScorer) scoreDevice(trust string) int {
	switch trust {
	case "corporate":
		return 0
	case "personal":
		return 50
	default:
		return 100
	}
}

// scoreBulkExport 批量导出评分
// <10 次 → 0；<100 次 → 50；≥100 次 → 100
func (r *RuleScorer) scoreBulkExport(hourlyAccess int) int {
	switch {
	case hourlyAccess < 10:
		return 0
	case hourlyAccess < 100:
		return 50
	default:
		return 100
	}
}

// segment 按选题风险分段映射到动作
// 0-30 绿色通道 / 31-70 黄色预警(强制MFA) / 71-100 红色拦截
func (r *RuleScorer) segment(total int) (level string, action string) {
	switch {
	case total <= 30:
		return "low", "allow"
	case total <= 70:
		return "medium", "mfa"
	default:
		return "high", "deny"
	}
}
