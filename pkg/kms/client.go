package kms

import (
	"context"
	"sync"

	pb "github.com/L1566/FileGuard/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client KMS gRPC 客户端，提供密钥管理远程调用
type Client struct {
	conn   *grpc.ClientConn
	client pb.KeyManagementServiceClient
	cache  sync.Map // 本地缓存当前 key_id
}

// NewClient 创建 KMS 客户端，连接至 addr（如 localhost:50051）
func NewClient(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:   conn,
		client: pb.NewKeyManagementServiceClient(conn),
	}, nil
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

// RotateKey 轮换指定密钥，返回新密钥的 key_id
func (c *Client) RotateKey(ctx context.Context, keyID string) (string, error) {
	resp, err := c.client.RotateKey(ctx, &pb.RotateKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		return "", err
	}
	return resp.NewKeyId, nil
}

// RevokeKey 吊销指定密钥，吊销后该密钥无法再用于加解密
func (c *Client) RevokeKey(ctx context.Context, keyID string) error {
	_, err := c.client.RevokeKey(ctx, &pb.RevokeKeyRequest{
		KeyId: keyID,
	})
	return err
}
