package risk

import "testing"

func TestSanitizeChineseID(t *testing.T) {
	tests := []struct{ input, want string }{
		{"110101199001011234", "****-ID-****"},
		{"开头无身份证号", "开头无身份证号"},
		{"身份证110101199001011234在这里", "身份证****-ID-****在这里"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizePhone(t *testing.T) {
	tests := []struct{ input, want string }{
		{"13812345678", "****-PHONE-****"},
		{"电话：13812345678，请记录", "电话：****-PHONE-****，请记录"},
		{"no phone here", "no phone here"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeEmail(t *testing.T) {
	tests := []struct{ input, want string }{
		{"alice@evcompany.com", "***@evcompany.com"},
		{"发送至 bob@test.cn 即可", "发送至 ***@test.cn 即可"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeIP(t *testing.T) {
	tests := []struct{ input, want string }{
		{"IP: 192.168.1.100", "IP: 192.168.*.*"},
		{"10.0.0.1", "10.0.*.*"},
		{"no ip", "no ip"},
	}
	for _, tt := range tests {
		got := Sanitize(tt.input)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeBankCard(t *testing.T) {
	input := "卡号6222021234567890请核对"
	want := "卡号****-BANK-****请核对"
	got := Sanitize(input)
	if got != want {
		t.Errorf("Sanitize(%q) = %q, want %q", input, got, want)
	}
}

func TestSanitizeEmpty(t *testing.T) {
	if Sanitize("") != "" {
		t.Error("empty input should return empty")
	}
}
