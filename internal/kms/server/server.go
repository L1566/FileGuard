package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	pb "github.com/L1566/FileGuard/api/proto"
	"github.com/L1566/FileGuard/pkg/crypto"
	"github.com/L1566/FileGuard/pkg/logger"
)

// KMSServer 密钥管理服务，支持内存操作 + 可选文件持久化
type KMSServer struct {
	pb.UnimplementedKeyManagementServiceServer
	mu       sync.RWMutex
	keys     map[string]string // key_id -> key_material (Base64)
	keysFile string            // 持久化文件路径（空 = 仅内存）
}

// NewKMSServer 创建 KMS 服务实例
// keysFile: 密钥持久化 JSON 文件路径，为空则仅使用内存存储
func NewKMSServer(keysFile string) *KMSServer {
	s := &KMSServer{
		keys:     make(map[string]string),
		keysFile: keysFile,
	}
	if keysFile != "" {
		s.loadKeys()
	}
	return s
}

// GenerateKey 生成新密钥，自动持久化
func (s *KMSServer) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	if req.Algorithm == "AES256" {
		keyMaterial, err := crypto.GenerateAESKey()
		if err != nil {
			return nil, err
		}
		keyID := generateKeyID()
		s.mu.Lock()
		s.keys[keyID] = keyMaterial
		s.mu.Unlock()
		s.saveKeys()
		return &pb.GenerateKeyResponse{
			KeyId:       keyID,
			KeyMaterial: keyMaterial,
		}, nil
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
}

// Encrypt 使用指定 key_id 加密数据
func (s *KMSServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	s.mu.RLock()
	keyMaterial, ok := s.keys[req.KeyId]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.KeyId)
	}
	ciphertext, err := crypto.AESEncrypt(req.Plaintext, keyMaterial)
	if err != nil {
		return nil, err
	}
	return &pb.EncryptResponse{Ciphertext: ciphertext}, nil
}

// Decrypt 使用指定 key_id 解密数据
func (s *KMSServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	s.mu.RLock()
	keyMaterial, ok := s.keys[req.KeyId]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key not found: %s", req.KeyId)
	}
	plaintext, err := crypto.AESDecrypt(req.Ciphertext, keyMaterial)
	if err != nil {
		return nil, err
	}
	return &pb.DecryptResponse{Plaintext: plaintext}, nil
}

// RotateKey 轮换密钥：生成新密钥保留旧密钥（旧密钥仅用于解密已有文件）
func (s *KMSServer) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	newKey, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, err
	}
	newID := generateKeyID()
	s.mu.Lock()
	s.keys[newID] = newKey
	s.mu.Unlock()
	s.saveKeys()
	return &pb.RotateKeyResponse{NewKeyId: newID}, nil
}

// RevokeKey 吊销密钥，吊销后立即持久化
func (s *KMSServer) RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	s.mu.Lock()
	delete(s.keys, req.KeyId)
	s.mu.Unlock()
	s.saveKeys()
	return &pb.RevokeKeyResponse{Success: true}, nil
}

// =============================================================================
// 持久化（JSON 文件）
// =============================================================================

// loadKeys 从文件加载密钥
func (s *KMSServer) loadKeys() {
	data, err := os.ReadFile(s.keysFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Infof("Key store file not found, starting with empty keyring: %s", s.keysFile)
			return
		}
		logger.Warnf("Failed to read key store %s: %v", s.keysFile, err)
		return
	}
	if len(data) == 0 {
		return
	}
	var kv map[string]string
	if err := json.Unmarshal(data, &kv); err != nil {
		logger.Warnf("Failed to parse key store %s: %v", s.keysFile, err)
		return
	}
	s.mu.Lock()
	for k, v := range kv {
		s.keys[k] = v
	}
	s.mu.Unlock()
	logger.Infof("Loaded %d keys from %s", len(kv), s.keysFile)
}

// saveKeys 将密钥写入文件
func (s *KMSServer) saveKeys() {
	if s.keysFile == "" {
		return
	}
	s.mu.RLock()
	data, err := json.MarshalIndent(s.keys, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		logger.Errorf("Failed to marshal keys: %v", err)
		return
	}
	dir := filepath.Dir(s.keysFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Errorf("Failed to create key store dir %s: %v", dir, err)
		return
	}
	if err := os.WriteFile(s.keysFile, data, 0600); err != nil {
		logger.Errorf("Failed to write key store %s: %v", s.keysFile, err)
	}
}

// =============================================================================
// 辅助函数
// =============================================================================

func generateKeyID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
