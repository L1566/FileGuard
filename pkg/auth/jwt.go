package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	UserID  string `json:"user_id"`
	Role    string `json:"role"`
	Project string `json:"project"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey []byte
	issuer    string
	expiry    time.Duration
}

func NewJWTManager(secretKey string, issuer string, expiry time.Duration) *JWTManager {
	return &JWTManager{
		secretKey: []byte(secretKey),
		issuer:    issuer,
		expiry:    expiry,
	}
}

func (m *JWTManager) Generate(userID, role, project string) (string, error) {
	claims := JWTClaims{
		UserID:  userID,
		Role:    role,
		Project: project,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.expiry)),
			Issuer:    m.issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

func (m *JWTManager) Verify(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return m.secretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
