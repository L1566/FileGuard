package risk

import "regexp"

var sanitizeRules = []struct {
	pattern *regexp.Regexp
	replace string
}{
	// 身份证号（18位，最后一位可能是数字或X）
	{regexp.MustCompile(`\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`), "****-ID-****"},
	// 手机号（中国大陆）
	{regexp.MustCompile(`\b1[3-9]\d{9}\b`), "****-PHONE-****"},
	// 邮箱
	{regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b`), "***@$1"},
	// IPv4 地址
	{regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b`), "$1.$2.*.*"},
	// 银行卡号（13-19位数字）
	{regexp.MustCompile(`\b\d{13,19}\b`), "****-BANK-****"},
}

// Sanitize 对输入文本执行 PII 脱敏，返回脱敏后的文本
func Sanitize(input string) string {
	if input == "" {
		return ""
	}
	result := input
	for _, rule := range sanitizeRules {
		result = rule.pattern.ReplaceAllString(result, rule.replace)
	}
	return result
}
