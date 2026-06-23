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
	Address string `mapstructure:"address"` // e.g. localhost:50051
}

// DLPSettings DLP 规则设置
type DLPSettings struct {
	RulesFile string `mapstructure:"rules_file"`
}

// WatermarkSettings 水印设置
type WatermarkSettings struct {
	FontPath string `mapstructure:"font_path"` // 水印字体文件路径
}

// MonitorSettings 文件监控设置（agent 使用）
type MonitorSettings struct {
	RootDir string `mapstructure:"root_dir"`
}

// GatewaySettings 网关连接设置（agent 使用）
type GatewaySettings struct {
	URL       string        `mapstructure:"url"`
	Heartbeat time.Duration `mapstructure:"heartbeat"` // e.g. 30s
}

// =============================================================================
// 各服务完整配置类型
// =============================================================================

// ServiceConfig 基础服务配置（适用于 audit / policy / kms 等简单服务）
type ServiceConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
}

// GatewayConfig 零信任网关配置
type GatewayConfig struct {
	Service ServiceSettings `mapstructure:"service"`
	Log     LogSettings     `mapstructure:"log"`
	JWT     JWTSettings     `mapstructure:"jwt"`
	Storage StorageSettings `mapstructure:"storage"`
	Policy  PolicySettings  `mapstructure:"policy"`
	Audit   AuditSettings   `mapstructure:"audit"`
	KMS       KMSSettings       `mapstructure:"kms"`
	DLP       DLPSettings       `mapstructure:"dlp"`
	Watermark WatermarkSettings `mapstructure:"watermark"`
}

// AgentConfig 终端代理配置
type AgentConfig struct {
	Service  ServiceSettings  `mapstructure:"service"`
	Log      LogSettings      `mapstructure:"log"`
	Monitor  MonitorSettings  `mapstructure:"monitor"`
	Gateway  GatewaySettings  `mapstructure:"gateway"`
	ClientID string           `mapstructure:"client_id"`
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

// LoadViper 返回 viper 实例，供需要自定义 unmarshal 的调用方使用
func LoadViper(configFile string) (*viper.Viper, error) {
	return newViper(configFile)
}
