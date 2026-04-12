package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/L1566/FileGuard/internal/agent/monitor"
	"github.com/L1566/FileGuard/internal/agent/reporter"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
)

type AgentConfig struct {
	Service struct {
		Name string `mapstructure:"name"`
	} `mapstructure:"service"`
	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
	Monitor struct {
		RootDir string `mapstructure:"root_dir"`
	} `mapstructure:"monitor"`
	Gateway struct {
		URL       string        `mapstructure:"url"`
		Heartbeat time.Duration `mapstructure:"heartbeat"`
	} `mapstructure:"gateway"`
	ClientID string `mapstructure:"client_id"`
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/agent.yaml", "config file path")
	flag.Parse()

	// 加载配置
	v, err := config.LoadViper(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	var cfg AgentConfig
	if err := v.Unmarshal(&cfg); err != nil {
		logger.Fatal("Failed to parse config: ", err)
	}

	// 初始化日志
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	// 创建监控器
	mon, err := monitor.NewMonitor()
	if err != nil {
		logger.Fatal("Failed to create monitor: ", err)
	}
	if err := mon.AddPath(cfg.Monitor.RootDir); err != nil {
		logger.Fatal("Failed to add watch path: ", err)
	}

	// 创建上报器
	rep := reporter.NewReporter(reporter.Config{
		GatewayURL:   cfg.Gateway.URL,
		HeartbeatInt: cfg.Gateway.Heartbeat,
		ClientID:     cfg.ClientID,
	}, mon.Events())

	ctx, cancel := context.WithCancel(context.Background())
	mon.Start(ctx)
	rep.Start(ctx)

	logger.Infof("Agent started, monitoring %s", cfg.Monitor.RootDir)

	// 优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	logger.Info("Shutting down agent...")
	cancel()
	mon.Stop()
	rep.Stop()
	time.Sleep(1 * time.Second)
}
