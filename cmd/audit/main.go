package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/L1566/FileGuard/internal/audit/handler" // 需要创建对应目录和文件
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/gorilla/mux"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/audit.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}

	logger.Init(cfg.Log.Level, cfg.Log.Format)

	r := mux.NewRouter()
	r.HandleFunc("/health", handler.HealthCheck).Methods("GET")

	addr := fmt.Sprintf(":%d", cfg.Service.Port)
	logger.Infof("Starting %s on %s", cfg.Service.Name, addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal("Server failed: ", err)
	}
}
