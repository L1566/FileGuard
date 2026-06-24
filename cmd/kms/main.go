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
