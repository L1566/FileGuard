package config

import (
	"strings"

	"github.com/spf13/viper"
)

// ServiceConfig 通用服务配置
type ServiceConfig struct {
	Service struct {
		Name string `mapstructure:"name"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"service"`

	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
}

func Load(configFile string) (*ServiceConfig, error) {
	v := viper.New()
	v.SetConfigFile(configFile)
	v.SetEnvPrefix("FILEGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg ServiceConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
