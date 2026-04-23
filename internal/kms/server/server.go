package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	pb "github.com/L1566/FileGuard/api/proto"
	"github.com/L1566/FileGuard/pkg/crypto"
)

type KMSServer struct {
	pb.UnimplementedKeyManagementServiceServer
	mu   sync.RWMutex
	keys map[string]string // key_id -> key_material (Base64)
}

func NewKMSServer() *KMSServer {
	return &KMSServer{
		keys: make(map[string]string),
	}
}

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
		return &pb.GenerateKeyResponse{
			KeyId:       keyID,
			KeyMaterial: keyMaterial,
		}, nil
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", req.Algorithm)
}

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

func (s *KMSServer) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	// 生成新密钥，保留旧密钥用于解密（实际需标记旧密钥为只解密）
	newKey, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, err
	}
	newID := generateKeyID()
	s.mu.Lock()
	s.keys[newID] = newKey
	s.mu.Unlock()
	return &pb.RotateKeyResponse{NewKeyId: newID}, nil
}

func (s *KMSServer) RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	s.mu.Lock()
	delete(s.keys, req.KeyId)
	s.mu.Unlock()
	return &pb.RevokeKeyResponse{Success: true}, nil
}

func generateKeyID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
