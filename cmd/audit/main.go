package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/L1566/FileGuard/api/proto/audit"
	"github.com/L1566/FileGuard/internal/audit/server"
	"github.com/L1566/FileGuard/pkg/audit"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// AuditConfig 审计服务扩展配置
type AuditConfig struct {
	Service config.ServiceSettings `mapstructure:"service"`
	Log     config.LogSettings     `mapstructure:"log"`
	Storage struct {
		LogFile string `mapstructure:"log_file"`
	} `mapstructure:"storage"`
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/audit.yaml", "config file path")
	flag.Parse()

	var cfg AuditConfig
	v, err := config.LoadViper(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	if err := v.Unmarshal(&cfg); err != nil {
		logger.Fatal("Failed to parse config: ", err)
	}
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	// 初始化审计日志存储
	fl, err := audit.NewFileLogger(cfg.Storage.LogFile)
	if err != nil {
		logger.Fatal("Failed to create audit logger: ", err)
	}
	defer fl.Close()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Service.Port))
	if err != nil {
		logger.Fatal("Failed to listen: ", err)
	}

	s := grpc.NewServer()
	pb.RegisterAuditServiceServer(s, server.NewAuditServer(fl))
	reflection.Register(s) // 支持 grpc_health_probe 等服务发现

	logger.Infof("%s gRPC server listening on port %d", cfg.Service.Name, cfg.Service.Port)
	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Fatal("Failed to serve: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down Audit Service...")
	s.GracefulStop()
}
