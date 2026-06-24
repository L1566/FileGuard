package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/L1566/FileGuard/api/proto/policy"
	"github.com/L1566/FileGuard/internal/policy/server"
	"github.com/L1566/FileGuard/pkg/abac"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "configs/policy.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadPolicy(configPath)
	if err != nil {
		logger.Fatal("Failed to load config: ", err)
	}
	logger.Init(cfg.Log.Level, cfg.Log.Format)

	// 加载初始规则
	var evaluator *abac.MemoryEvaluator
	if cfg.Policy.RulesFile != "" {
		rules, err := abac.LoadRulesFromFile(cfg.Policy.RulesFile)
		if err != nil {
			logger.Warnf("Failed to load rules from %s: %v (starting empty)", cfg.Policy.RulesFile, err)
		}
		evaluator = abac.NewMemoryEvaluator(rules)
	} else {
		evaluator = abac.NewMemoryEvaluator(nil)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Service.Port))
	if err != nil {
		logger.Fatal("Failed to listen: ", err)
	}

	s := grpc.NewServer()
	pb.RegisterPolicyServiceServer(s, server.NewPolicyServer(evaluator, cfg.Policy.RulesFile))
	reflection.Register(s)

	logger.Infof("%s gRPC server listening on port %d", cfg.Service.Name, cfg.Service.Port)
	go func() {
		if err := s.Serve(lis); err != nil {
			logger.Fatal("Failed to serve: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down Policy Service...")
	s.GracefulStop()
}
