package handler

import (
	"net/http"

	httputil "github.com/L1566/FileGuard/pkg/http"
)

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	httputil.Success(w, map[string]string{"status": "ok"})
}
