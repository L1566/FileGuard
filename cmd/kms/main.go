package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/L1566/FileGuard/api/proto"
	"github.com/L1566/FileGuard/internal/kms/server"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/kms.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadKMS(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Service.Port))
	if err != nil {
		logger.Fatal("Failed to listen: ", err)
	}

	var grpcOpts []grpc.ServerOption
	if cfg.TLS.Enabled {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			logger.Fatal("Failed to load TLS credentials: ", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		logger.Info("KMS TLS enabled")
	}

	s := grpc.NewServer(grpcOpts...)
	pb.RegisterKeyManagementServiceServer(s, server.NewKMSServer(cfg.KeyStore.File))

	// 注册标准 gRPC Health Check 服务（供 docker-compose grpc_health_probe 使用）
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	logger.Infof("KMS server listening on port %d", cfg.Service.Port)
	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Fatal("Failed to serve: ", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down KMS...")
	s.GracefulStop()
}
