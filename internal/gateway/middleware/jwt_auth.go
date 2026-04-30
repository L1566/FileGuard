package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/L1566/FileGuard/pkg/auth"
	httputil "github.com/L1566/FileGuard/pkg/http"
	"github.com/L1566/FileGuard/pkg/logger"
)

type contextkeyJwtAuth string

const ClaimsKey contextkeyJwtAuth = "claims"

func JWTAuthMiddleware(jwtMgr *auth.JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httputil.Error(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				httputil.Error(w, http.StatusUnauthorized, "invalid Authorization header format")
				return
			}
			tokenString := parts[1]
			claims, err := jwtMgr.Verify(tokenString)
			if err != nil {
				logger.Warnf("JWT verification failed: %v", err)
				httputil.Error(w, http.StatusUnauthorized, "invalid token")
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims 从 context 获取 claims
func GetClaims(ctx context.Context) *auth.JWTClaims {
	if claims, ok := ctx.Value(ClaimsKey).(*auth.JWTClaims); ok {
		return claims
	}
	return nil
}
