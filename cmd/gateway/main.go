package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/L1566/FileGuard/internal/gateway/handler"
	"github.com/L1566/FileGuard/internal/gateway/middleware"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/gorilla/mux"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/gateway.yaml", "config file path")
	flag.Parse()

	// 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}

	// 初始化日志
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	// 创建路由
	r := mux.NewRouter()
	r.Use(middleware.Logging)

	r.HandleFunc("/health", handler.HealthCheck).Methods("GET")

	addr := fmt.Sprintf(":%d", cfg.Service.Port)
	logger.Infof("Starting %s on %s", cfg.Service.Name, addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal("Server failed: ", err)
	}
}
