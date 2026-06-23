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
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/kms.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Service.Port))
	if err != nil {
		logger.Fatal("Failed to listen: ", err)
	}
	s := grpc.NewServer()
	pb.RegisterKeyManagementServiceServer(s, server.NewKMSServer())

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
