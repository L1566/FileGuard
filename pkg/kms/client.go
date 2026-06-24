package kms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	pb "github.com/L1566/FileGuard/api/proto"
	"github.com/L1566/FileGuard/pkg/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Client KMS gRPC 客户端，提供密钥管理远程调用
type Client struct {
	conn   *grpc.ClientConn
	client pb.KeyManagementServiceClient
	cache  sync.Map // 本地缓存当前 key_id
}

// NewClient 创建 KMS 客户端，连接至 addr（如 localhost:50051）。
// tlsCfg 为 nil 或 disabled 时使用 insecure 连接。
func NewClient(addr string, tlsCfg *config.TLSSettings) (*Client, error) {
	var opts []grpc.DialOption
	if tlsCfg != nil && tlsCfg.Enabled {
		creds, err := loadClientTLSCreds(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("KMS TLS: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}

	// 验证连接可用性：轮询 GetState() 直至 Ready 或超时
	conn.Connect()
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastState connectivity.State
	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			break
		}
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			conn.Close()
			return nil, fmt.Errorf("KMS gRPC connect to %s: %s", addr, state.String())
		}
		lastState = state

		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				conn.Close()
				return nil, fmt.Errorf("KMS gRPC connect to %s: timed out after 5s (last state: %s)", addr, lastState.String())
			}
		}
	}

	return &Client{
		conn:   conn,
		client: pb.NewKeyManagementServiceClient(conn),
	}, nil
}

// loadClientTLSCreds 加载客户端 TLS 凭据
func loadClientTLSCreds(cfg *config.TLSSettings) (credentials.TransportCredentials, error) {
	tlsCfg := &tls.Config{}
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", cfg.CAFile, err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("parse CA cert %s failed", cfg.CAFile)
		}
		tlsCfg.RootCAs = caPool
	}
	return credentials.NewTLS(tlsCfg), nil
}

// Close 关闭 gRPC 连接
func (c *Client) Close() error {
	return c.conn.Close()
}

// Encrypt 加密数据，返回 Base64 密文和使用的 key_id
func (c *Client) Encrypt(ctx context.Context, plaintext []byte) (ciphertext string, keyID string, err error) {
	const cacheKey = "current_key_id"
	var currentKeyID string
	if v, ok := c.cache.Load(cacheKey); ok {
		currentKeyID = v.(string)
	} else {
		// 首次调用，向服务端生成一个新密钥
		resp, err := c.client.GenerateKey(ctx, &pb.GenerateKeyRequest{
			Algorithm: "AES256",
			Size:      256,
		})
		if err != nil {
			return "", "", err
		}
		currentKeyID = resp.KeyId
		c.cache.Store(cacheKey, currentKeyID)
	}

	encResp, err := c.client.Encrypt(ctx, &pb.EncryptRequest{
		KeyId:     currentKeyID,
		Plaintext: plaintext,
	})
	if err != nil {
		return "", "", err
	}
	return encResp.Ciphertext, currentKeyID, nil
}

// Decrypt 解密密文，需提供加密时使用的 key_id
func (c *Client) Decrypt(ctx context.Context, ciphertext string, keyID string) ([]byte, error) {
	resp, err := c.client.Decrypt(ctx, &pb.DecryptRequest{
		KeyId:      keyID,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

// RotateKey 轮换指定密钥，返回新密钥的 key_id 并更新本地缓存
func (c *Client) RotateKey(ctx context.Context, keyID string) (string, error) {
	resp, err := c.client.RotateKey(ctx, &pb.RotateKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return "", err
	}
	c.cache.Store("current_key_id", resp.NewKeyId)
	return resp.NewKeyId, nil
}

// RevokeKey 吊销指定密钥并清除本地缓存
func (c *Client) RevokeKey(ctx context.Context, keyID string) error {
	_, err := c.client.RevokeKey(ctx, &pb.RevokeKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return err
	}
	// 如果吊销的是当前使用的密钥，清除缓存强制下次 Encrypt 生成新密钥
	if v, ok := c.cache.Load("current_key_id"); ok && v.(string) == keyID {
		c.cache.Delete("current_key_id")
	}
	return nil
}
