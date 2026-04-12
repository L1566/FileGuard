package middleware

import (
	"context"
	"net/http"

	"github.com/L1566/FileGuard/pkg/abac"
)

type contextKey string

const UserSubjectKey contextKey = "user_subject"

// AuthMiddleware 从请求头提取用户信息，构造 Subject
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟：从 Header 获取用户身份（实际可对接 JWT）
		userID := r.Header.Get("X-User-Id")
		if userID == "" {
			userID = "anonymous"
		}
		role := r.Header.Get("X-User-Role")
		if role == "" {
			role = "guest"
		}
		project := r.Header.Get("X-User-Project")

		subject := abac.Subject{
			ID:      userID,
			Type:    "user",
			Role:    role,
			Project: project,
			Attributes: map[string]interface{}{
				"source": "header",
			},
		}
		ctx := context.WithValue(r.Context(), UserSubjectKey, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSubject 从 context 中获取 Subject
func GetSubject(ctx context.Context) abac.Subject {
	if sub, ok := ctx.Value(UserSubjectKey).(abac.Subject); ok {
		return sub
	}
	return abac.Subject{ID: "unknown", Role: "guest"}
}
