package middleware

import (
	"net/http"
	"time"

	"github.com/L1566/FileGuard/pkg/logger"
)

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Infof("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}
