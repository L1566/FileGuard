package handler

import (
	"encoding/json"
	"net/http"

	"github.com/L1566/FileGuard/internal/auth"
	pkg_auth "github.com/L1566/FileGuard/pkg/auth"
	httputil "github.com/L1566/FileGuard/pkg/http"
	"github.com/L1566/FileGuard/pkg/logger"
)

type AuthHandler struct {
	userStore *auth.UserStore
	jwtMgr    *pkg_auth.JWTManager
	issuer    string
}

func NewAuthHandler(userStore *auth.UserStore, jwtMgr *pkg_auth.JWTManager, issuer string) *AuthHandler {
	return &AuthHandler{
		userStore: userStore,
		jwtMgr:    jwtMgr,
		issuer:    issuer,
	}
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Passcode string `json:"passcode"` // TOTP 验证码（MFA启用时必须）
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token string `json:"token"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request")
		return
	}

	// 验证用户名密码
	user, ok := h.userStore.GetUser(req.Username)
	if !ok || user.Password != req.Password {
		httputil.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// 如果用户启用了 MFA，必须验证 passcode
	if user.MFAEnabled {
		if req.Passcode == "" {
			httputil.Error(w, http.StatusUnauthorized, "MFA code required")
			return
		}
		if !pkg_auth.ValidateTOTP(user.TOTPSecret, req.Passcode) {
			httputil.Error(w, http.StatusUnauthorized, "invalid MFA code")
			return
		}
	}

	// 生成 JWT token
	token, err := h.jwtMgr.Generate(user.ID, user.Role, user.Project)
	if err != nil {
		logger.Errorf("Failed to generate token: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "login failed")
		return
	}

	httputil.Success(w, LoginResponse{Token: token})
}

// SetupMFA 为用户生成 TOTP 密钥并返回二维码
func (h *AuthHandler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	// 从 JWT 中获取用户ID（需要认证）
	claims, ok := r.Context().Value("claims").(*pkg_auth.JWTClaims)
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	secret, qrURL, err := pkg_auth.GenerateTOTPSecret(claims.UserID, h.issuer)
	if err != nil {
		logger.Errorf("Failed to generate TOTP secret: %v", err)
		httputil.Error(w, http.StatusInternalServerError, "setup failed")
		return
	}

	// 保存 secret 到用户存储（实际应要求用户验证后再保存）
	h.userStore.SetTOTPSecret(claims.UserID, secret)

	httputil.Success(w, map[string]interface{}{
		"secret":     secret,
		"qrcode_url": qrURL,
	})
}

// VerifyMFA 验证 MFA 码并启用（可选）
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passcode string `json:"passcode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request")
		return
	}
	claims, ok := r.Context().Value("claims").(*pkg_auth.JWTClaims)
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	user, ok := h.userStore.GetUser(claims.UserID)
	if !ok {
		httputil.Error(w, http.StatusNotFound, "user not found")
		return
	}
	if !pkg_auth.ValidateTOTP(user.TOTPSecret, req.Passcode) {
		httputil.Error(w, http.StatusBadRequest, "invalid passcode")
		return
	}
	// 已经保存过 secret，这里可以标记为已验证
	httputil.Success(w, map[string]string{"status": "MFA enabled"})
}
