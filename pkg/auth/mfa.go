package auth

import (
	"crypto/rand"
	"encoding/base32"
	"net/url"

	"github.com/pquerna/otp/totp"
)

type Key struct {
	orig string
	url  *url.URL
}

// GenerateTOTPSecret 生成一个新的 TOTP 密钥，并返回密钥字符串和二维码数据URL
func GenerateTOTPSecret(user, issuer string) (secret string, qrCodeURL string, err error) {
	// 生成随机密钥
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", err
	}
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)

	// 生成 otpauth URL
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user,
		Secret:      []byte(secret),
	})
	if err != nil {
		return "", "", err
	}
	secret = key.Secret()
	qrCodeURL = key.URL()
	return secret, qrCodeURL, nil
}

// ValidateTOTP 验证用户输入的 TOTP 码是否正确
func ValidateTOTP(secret, passcode string) bool {
	return totp.Validate(passcode, secret)
}
