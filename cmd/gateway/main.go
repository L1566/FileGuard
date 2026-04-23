package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/L1566/FileGuard/internal/gateway/handler"
	"github.com/L1566/FileGuard/internal/gateway/middleware"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/kms"
	"github.com/L1566/FileGuard/pkg/logger"
	"github.com/L1566/FileGuard/pkg/storage"
	"github.com/gorilla/mux"
)

type GatewayConfig struct {
	Service struct {
		Name string `mapstructure:"name"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"service"`
	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
	Storage struct {
		Type    string `mapstructure:"type"` // "local"
		RootDir string `mapstructure:"root_dir"`
	} `mapstructure:"storage"`
	Policy struct {
		RulesFile string `mapstructure:"rules_file"`
	} `mapstructure:"policy"`
	Audit struct {
		LogFile string `mapstructure:"log_file"`
	} `mapstructure:"audit"`
	Kms struct {
		Address string `mapstructure:"address"`
	} `mapstructure:"kms"`
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/gateway.yaml", "config file path")
	flag.Parse()

	// 加载配置
	var cfg GatewayConfig
	v, err := config.LoadViper(configPath) // 复用之前的 Load，但需扩展
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	if err := v.Unmarshal(&cfg); err != nil {
		logger.Fatal("Failed to parse config: ", err)
	}

	// 初始化日志
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	// 初始化存储
	var store storage.Storage
	switch cfg.Storage.Type {
	case "local":
		store, err = storage.NewLocalFileSystem(cfg.Storage.RootDir)
		if err != nil {
			logger.Fatal("Failed to init storage: ", err)
		}
	default:
		logger.Fatalf("Unsupported storage type: %s", cfg.Storage.Type)
	}

	// 初始化 ABAC 评估器
	rules, err := abac.LoadRulesFromFile(cfg.Policy.RulesFile)
	if err != nil {
		logger.Warnf("Failed to load rules file: %v, using empty rules", err)
		rules = []abac.Rule{}
	}
	evaluator := abac.NewMemoryEvaluator(rules)

	// 初始化审计日志
	auditLogger, err := audit.NewFileLogger(cfg.Audit.LogFile)
	if err != nil {
		logger.Fatal("Failed to init audit logger: ", err)
	}
	defer auditLogger.Close()

	// 创建路由
	r := mux.NewRouter()
	r.Use(middleware.Logging)
	r.Use(middleware.AuthMiddleware)

	// 初始化 KMS 客户端
	kmsClient, err := kms.NewClient(cfg.Kms.Address)
	if err != nil {
		logger.Fatal("Failed to connect to KMS: ", err)
	}
	defer kmsClient.Close()

	// 创建文件处理器时传入 kmsClient
	fileHandler := handler.NewFileHandler(store, evaluator, auditLogger, kmsClient)
	r.HandleFunc("/health", handler.HealthCheck).Methods("GET")
	r.HandleFunc("/file/{path:.*}", fileHandler.GetFile).Methods("GET")
	r.HandleFunc("/file/{path:.*}", fileHandler.PutFile).Methods("PUT")
	r.HandleFunc("/api/agent/event", handler.AgentEventHandler).Methods("POST")
	r.HandleFunc("/api/agent/heartbeat", handler.AgentHeartbeatHandler).Methods("POST")

	addr := fmt.Sprintf(":%d", cfg.Service.Port)
	logger.Infof("Starting %s on %s", cfg.Service.Name, addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal("Server failed: ", err)
	}
}
