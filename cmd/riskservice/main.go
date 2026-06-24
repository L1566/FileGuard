package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/L1566/FileGuard/internal/riskservice/handler"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/risk"
	"github.com/gorilla/mux"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/riskservice.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadRiskService(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	provider, err := risk.NewProvider(cfg.LLM.Provider, cfg.LLM.Model, cfg.LLM.Endpoint)
	if err != nil {
		logger.Fatal("Failed to create LLM provider: ", err)
	}

	scorer, err := risk.NewScorer(risk.ScorerConfig{
		Provider:   provider,
		Model:      cfg.LLM.Model,
		APIKeyEnv:  cfg.LLM.APIKeyEnv,
		Timeout:    cfg.LLM.Timeout,
		MaxRetries: cfg.LLM.MaxRetries,
		CacheSize:  cfg.Cache.MaxEntries,
		CacheTTL:   cfg.Cache.TTL,
	})
	if err != nil {
		logger.Fatal("Failed to create scorer: ", err)
	}

	h := handler.NewHandler(scorer)
	r := mux.NewRouter()
	r.HandleFunc("/health", h.HealthCheck).Methods("GET")
	r.HandleFunc("/api/risk/evaluate", h.Evaluate).Methods("POST")

	addr := fmt.Sprintf(":%d", cfg.Service.Port)
	logger.Infof("Starting Risk Service on %s", addr)

	go func() {
		var err error
		if cfg.TLS.Enabled {
			logger.Info("Risk Service TLS enabled")
			err = http.ListenAndServeTLS(addr, cfg.TLS.CertFile, cfg.TLS.KeyFile, r)
		} else {
			err = http.ListenAndServe(addr, r)
		}
		if err != nil {
			logger.Fatal("Server failed: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down Risk Service...")
}
