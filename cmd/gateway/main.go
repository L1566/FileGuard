package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/L1566/FileGuard/internal/auth"
	"github.com/L1566/FileGuard/internal/gateway/handler"
	"github.com/L1566/FileGuard/internal/gateway/middleware"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/audit"
	pkg_auth "github.com/L1566/FileGuard/pkg/auth"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/dlp"
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
	KMS struct {
		Address string `mapstructure:"address"`
	} `mapstructure:"kms"`
	DLP struct {
		RulesFile string `mapstructure:"rules_file"`
	} `mapstructure:"dlp"`
	JWT struct {
		SecretKey string        `mapstructure:"secret_key"`
		Issuer    string        `mapstructure:"issuer"`
		Expiry    time.Duration `mapstructure:"expiry"`
	} `mapstructure:"jwt"`
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

	// 初始化 DLP 规则集和检测器
	dlpRuleSet := dlp.NewRuleSet()
	if err := dlpRuleSet.LoadFromFile(cfg.DLP.RulesFile); err != nil {
		logger.Warnf("Failed to load DLP rules: %v", err)
	}
	dlpDetector := dlp.NewDetector(dlpRuleSet)

	// 初始化 ABAC 评估器
	rules, err := abac.LoadRulesFromFile(cfg.Policy.RulesFile)
	if err != nil {
		logger.Warnf("Failed to load rules file: %v, using empty rules", err)
		rules = []abac.Rule{}
	}
	evaluator := abac.NewMemoryEvaluator(rules)

	// 启动规则热加载
	if err := abac.WatchRuleFile(evaluator, cfg.Policy.RulesFile); err != nil {
		logger.Warnf("Failed to start rule watcher: %v", err)
	}

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
	kmsClient, err := kms.NewClient(cfg.KMS.Address)
	if err != nil {
		logger.Fatal("Failed to connect to KMS: ", err)
	}
	defer kmsClient.Close()

	// 初始化JWT
	jwtMgr := pkg_auth.NewJWTManager(cfg.JWT.SecretKey, cfg.JWT.Issuer, cfg.JWT.Expiry)
	userStore := auth.NewUserStore()
	authHandler := handler.NewAuthHandler(userStore, jwtMgr, cfg.JWT.Issuer)

	// 创建文件处理器
	fileHandler := handler.NewFileHandler(store, evaluator, auditLogger, kmsClient, dlpDetector)

	// ========== 公开路由（无需 JWT） ==========
	r.HandleFunc("/health", handler.HealthCheck).Methods("GET")
	r.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")

	// ========== 需要 JWT 验证的 API 路由 ==========
	apiProtected := r.PathPrefix("/api").Subrouter()
	apiProtected.Use(middleware.JWTAuthMiddleware(jwtMgr))

	// 认证相关（需 JWT）
	apiProtected.HandleFunc("/auth/setup-mfa", authHandler.SetupMFA).Methods("POST")
	apiProtected.HandleFunc("/auth/verify-mfa", authHandler.VerifyMFA).Methods("POST")

	// Agent 相关
	apiProtected.HandleFunc("/agent/event", handler.AgentEventHandler).Methods("POST")
	apiProtected.HandleFunc("/agent/heartbeat", handler.AgentHeartbeatHandler).Methods("POST")

	// 策略管理 API
	policyAPI := handler.NewPolicyAPI(evaluator)
	apiProtected.HandleFunc("/policy/rules", policyAPI.GetRules).Methods("GET")
	apiProtected.HandleFunc("/policy/rules", policyAPI.AddRule).Methods("POST")
	apiProtected.HandleFunc("/policy/rules/{id}", policyAPI.UpdateRule).Methods("PUT")
	apiProtected.HandleFunc("/policy/rules/{id}", policyAPI.DeleteRule).Methods("DELETE")

	// ========== 文件访问路由（需 JWT） ==========
	fileProtected := r.PathPrefix("/file").Subrouter()
	fileProtected.Use(middleware.JWTAuthMiddleware(jwtMgr))
	fileProtected.HandleFunc("/{path:.*}", fileHandler.GetFile).Methods("GET")
	fileProtected.HandleFunc("/{path:.*}", fileHandler.PutFile).Methods("PUT")

	addr := fmt.Sprintf(":%d", cfg.Service.Port)
	logger.Infof("Starting %s on %s", cfg.Service.Name, addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal("Server failed: ", err)
	}
}
