package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// =============================================================================
// 可复用配置片段 —— 各服务 YAML 文件的通用节点
// =============================================================================

// ServiceSettings 服务基础设置
type ServiceSettings struct {
	Name string `mapstructure:"name"`
	Port int    `mapstructure:"port"`
}

// LogSettings 日志设置
type LogSettings struct {
	Level  string `mapstructure:"level"`  // debug, info, warn, error
	Format string `mapstructure:"format"` // text, json
}

// JWTSettings JWT 认证设置
type JWTSettings struct {
	SecretKey string        `mapstructure:"secret_key"`
	Issuer    string        `mapstructure:"issuer"`
	Expiry    time.Duration `mapstructure:"expiry"` // e.g. 24h
}

// StorageSettings 存储后端设置
type StorageSettings struct {
	Type    string `mapstructure:"type"`     // local, s3, minio
	RootDir string `mapstructure:"root_dir"` // 本地存储根目录
}

// PolicySettings 策略引擎设置
type PolicySettings struct {
	RulesFile string `mapstructure:"rules_file"`
}

// AuditSettings 审计日志设置
type AuditSettings struct {
	LogFile string `mapstructure:"log_file"`
}

// KMSSettings KMS 连接设置
type KMSSettings struct {
	Address string      `mapstructure:"address"` // e.g. localhost:50051
	TLS     TLSSettings `mapstructure:"tls"`
}

// TLSSettings TLS 传输加密设置
type TLSSettings struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"` // 可选：自定义 CA（用于自签名证书）
}

// DLPSettings DLP 规则设置
type DLPSettings struct {
	RulesFile string `mapstructure:"rules_file"`
}

// WatermarkSettings 水印设置
type WatermarkSettings struct {
	FontPath string `mapstructure:"font_path"` // 水印字体文件路径
}

// KeyStoreSettings KMS 密钥存储设置
type KeyStoreSettings struct {
	File string `mapstructure:"file"` // 密钥持久化文件路径
}

// MonitorSettings 文件监控设置（agent 使用）
type MonitorSettings struct {
	RootDir string `mapstructure:"root_dir"`
}

// GatewaySettings 网关连接设置（agent 使用）
type GatewaySettings struct {
	URL       string        `mapstructure:"url"`
	Heartbeat time.Duration `mapstructure:"heartbeat"` // e.g. 30s
	TLS       TLSSettings   `mapstructure:"tls"`
}

// RiskSettings 风险评分设置（Gateway 侧）
type RiskSettings struct {
	Enabled      bool          `mapstructure:"enabled"`
	Mode         string        `mapstructure:"mode"`          // shadow | monitor | active
	ServiceURL   string        `mapstructure:"service_url"`   // e.g. http://localhost:8090
	Timeout      time.Duration `mapstructure:"timeout"`       // e.g. 15s
	Fallback     string        `mapstructure:"fallback"`      // allow | deny | abac_only
	TrustedCIDRs []string      `mapstructure:"trusted_cidrs"` // 额外可信 IP 段（除私有 IP 外）
	TLS          TLSSettings   `mapstructure:"tls"`
}

// RiskServiceConfig Risk Service 自身配置
type RiskServiceConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
	LLM     LLMSettings     `mapstructure:"llm"`
	Cache   CacheSettings   `mapstructure:"cache"`
	TLS     TLSSettings     `mapstructure:"tls"`
}

type LLMSettings struct {
	Provider   string        `mapstructure:"provider"`    // anthropic | openai | deepseek | google | groq
	Model      string        `mapstructure:"model"`       // 模型名称
	Endpoint   string        `mapstructure:"endpoint"`    // 可选：留空使用内置默认，填写则覆盖
	APIKeyEnv  string        `mapstructure:"api_key_env"` // API Key 环境变量名
	Timeout    time.Duration `mapstructure:"timeout"`
	MaxRetries int           `mapstructure:"max_retries"`
}

type CacheSettings struct {
	MaxEntries int           `mapstructure:"max_entries"`
	TTL        time.Duration `mapstructure:"ttl"`
}

// =============================================================================
// 各服务完整配置类型
// =============================================================================

// ServiceConfig 基础服务配置（适用于 audit / policy 等简单服务）
type ServiceConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
}

// KMSConfig KMS 密钥管理服务配置
type KMSConfig struct {
	Service  ServiceSettings  `mapstructure:"service"`
	Log      LogSettings      `mapstructure:"log"`
	KeyStore KeyStoreSettings `mapstructure:"key_store"`
	TLS      TLSSettings      `mapstructure:"tls"`
}

// GatewayConfig 零信任网关配置
type GatewayConfig struct {
	Service   ServiceSettings   `mapstructure:"service"`
	Log       LogSettings       `mapstructure:"log"`
	JWT       JWTSettings       `mapstructure:"jwt"`
	Storage   StorageSettings   `mapstructure:"storage"`
	Policy    PolicySettings    `mapstructure:"policy"`
	Audit     AuditSettings     `mapstructure:"audit"`
	KMS       KMSSettings       `mapstructure:"kms"`
	DLP       DLPSettings       `mapstructure:"dlp"`
	Watermark WatermarkSettings `mapstructure:"watermark"`
	Risk      RiskSettings      `mapstructure:"risk"`
	TLS       TLSSettings       `mapstructure:"tls"`
}

// AgentConfig 终端代理配置
type AgentConfig struct {
	Service  ServiceSettings  `mapstructure:"service"`
	Log      LogSettings      `mapstructure:"log"`
	Monitor  MonitorSettings  `mapstructure:"monitor"`
	Gateway  GatewaySettings  `mapstructure:"gateway"`
	ClientID string           `mapstructure:"client_id"`
}

// AuditConfig 审计服务配置
type AuditConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
	Storage struct {
		LogFile string `mapstructure:"log_file"`
	} `mapstructure:"storage"`
}

// PolicyConfig 策略服务配置
type PolicyConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
	Policy  struct {
		RulesFile string `mapstructure:"rules_file"`
	} `mapstructure:"policy"`
}

// =============================================================================
// 加载函数
// =============================================================================

// newViper 创建预配置的 viper 实例，统一环境变量前缀
func newViper(configFile string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigFile(configFile)
	v.SetEnvPrefix("FILEGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	return v, nil
}

// Load 加载基础服务配置（audit / policy / kms 等）
func Load(configFile string) (*ServiceConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg ServiceConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadKMS 加载 KMS 配置
func LoadKMS(configFile string) (*KMSConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg KMSConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadGateway 加载网关配置
func LoadGateway(configFile string) (*GatewayConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg GatewayConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadRiskService 加载 Risk Service 配置
func LoadRiskService(configFile string) (*RiskServiceConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg RiskServiceConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadAgent 加载终端代理配置
func LoadAgent(configFile string) (*AgentConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg AgentConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadAudit 加载审计服务配置
func LoadAudit(configFile string) (*AuditConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg AuditConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadPolicy 加载策略服务配置
func LoadPolicy(configFile string) (*PolicyConfig, error) {
	v, err := newViper(configFile)
	if err != nil {
		return nil, err
	}
	var cfg PolicyConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadViper 返回 viper 实例，供需要自定义 unmarshal 的调用方使用
func LoadViper(configFile string) (*viper.Viper, error) {
	return newViper(configFile)
}
