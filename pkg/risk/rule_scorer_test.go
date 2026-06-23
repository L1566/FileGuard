package risk

import "testing"

func TestRuleScorer_OffHours(t *testing.T) {
	rs := NewRuleScorer()

	// 工作时间
	resp := rs.Score(ScoreInput{
		IsWorkHours: true, IPRiskLevel: "intranet",
		DeviceTrust: "corporate", HourlyAccess: 0,
	})
	if resp.RiskScore > 0.1 {
		t.Errorf("work hours should be low risk, got score=%.2f", resp.RiskScore)
	}
	if resp.Recommendation != "allow" {
		t.Errorf("work hours should allow, got %s", resp.Recommendation)
	}
}

func TestRuleScorer_ForeignHighRisk(t *testing.T) {
	rs := NewRuleScorer()

	// 全部高风险: 凌晨 + 境外 + 未注册设备 + 大量访问
	resp := rs.Score(ScoreInput{
		IsWorkHours: false, IsDeepNight: true,
		IPRiskLevel: "foreign", DeviceTrust: "unregistered", HourlyAccess: 150,
	})
	// offHours(100)*20 + ip(100)*30 + device(100)*25 + bulk(100)*25 = 10000/100 = 100
	total := int(resp.RiskScore * 100)
	t.Logf("all high-risk: score=%.2f total=%d action=%s", resp.RiskScore, total, resp.Recommendation)

	if total != 100 {
		t.Errorf("expected total=100, got %d", total)
	}
	if resp.Recommendation != "deny" {
		t.Errorf("all high-risk should deny, got %s", resp.Recommendation)
	}
}

func TestRuleScorer_选题Example(t *testing.T) {
	rs := NewRuleScorer()

	// 选题中的示例: 凌晨3点 + 境外 + 个人设备 + >1000条导出
	// offHours(100)*20% + ip(100)*30% + device(50)*25% + bulk(100)*25%
	// = (2000 + 3000 + 1250 + 2500)/100 = 87.5
	resp := rs.Score(ScoreInput{
		IsWorkHours: false, IsDeepNight: true,
		IPRiskLevel: "foreign", DeviceTrust: "personal", HourlyAccess: 150,
	})
	total := int(resp.RiskScore * 100)
	t.Logf("score=%.2f total=%d level=%s action=%s reason=%s",
		resp.RiskScore, total, resp.RiskLevel, resp.Recommendation, resp.Reason)

	if total != 87 {
		t.Errorf("expected ~87, got %d", total)
	}
	if resp.Recommendation != "deny" {
		t.Errorf("score >70 should deny, got %s", resp.Recommendation)
	}
}

func TestRuleScorer_MediumRisk(t *testing.T) {
	rs := NewRuleScorer()

	// 中风险: 晚上 + 国内异地 + 个人设备 + 中等访问
	// offHours(50)*20 + ip(50)*30 + device(50)*25 + bulk(50)*25 = (1000+1500+1250+1250)/100 = 50
	resp := rs.Score(ScoreInput{
		IsWorkHours: false, IsDeepNight: false,
		IPRiskLevel: "domestic", DeviceTrust: "personal", HourlyAccess: 30,
	})
	total := int(resp.RiskScore * 100)
	t.Logf("medium risk: score=%.2f total=%d action=%s", resp.RiskScore, total, resp.Recommendation)

	if total != 50 {
		t.Errorf("expected total=50, got %d", total)
	}
	if resp.Recommendation != "mfa" {
		t.Errorf("medium risk should trigger mfa, got %s", resp.Recommendation)
	}
}

func TestRuleScorer_Segments(t *testing.T) {
	rs := NewRuleScorer()

	tests := []struct {
		name  string
		total int
		want  string
	}{
		{"green_0", 0, "allow"},
		{"green_30", 30, "allow"},
		{"yellow_31", 31, "mfa"},
		{"yellow_70", 70, "mfa"},
		{"red_71", 71, "deny"},
		{"red_100", 100, "deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, action := rs.segment(tt.total)
			if action != tt.want {
				t.Errorf("total=%d action=%s, want %s", tt.total, action, tt.want)
			}
			_ = level
		})
	}
}

func TestRuleScorer_FactorScores(t *testing.T) {
	rs := NewRuleScorer()

	if s := rs.scoreOffHours(true, false); s != 0 {
		t.Errorf("work hours -> 0, got %d", s)
	}
	if s := rs.scoreOffHours(false, false); s != 50 {
		t.Errorf("off hours (evening) -> 50, got %d", s)
	}
	if s := rs.scoreOffHours(false, true); s != 100 {
		t.Errorf("off hours (deep night) -> 100, got %d", s)
	}
	if s := rs.scoreIP("intranet"); s != 0 {
		t.Errorf("intranet -> 0, got %d", s)
	}
	if s := rs.scoreIP("domestic"); s != 50 {
		t.Errorf("domestic -> 50, got %d", s)
	}
	if s := rs.scoreIP("foreign"); s != 100 {
		t.Errorf("foreign -> 100, got %d", s)
	}
	if s := rs.scoreDevice("corporate"); s != 0 {
		t.Errorf("corporate -> 0, got %d", s)
	}
	if s := rs.scoreDevice("personal"); s != 50 {
		t.Errorf("personal -> 50, got %d", s)
	}
	if s := rs.scoreDevice("unregistered"); s != 100 {
		t.Errorf("unregistered -> 100, got %d", s)
	}
	if s := rs.scoreBulkExport(5); s != 0 {
		t.Errorf("bulk(5) -> 0, got %d", s)
	}
	if s := rs.scoreBulkExport(50); s != 50 {
		t.Errorf("bulk(50) -> 50, got %d", s)
	}
	if s := rs.scoreBulkExport(100); s != 100 {
		t.Errorf("bulk(100) -> 100, got %d", s)
	}
}
