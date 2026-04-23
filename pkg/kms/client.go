package kms

import (
	"context"
	"sync"

	pb "github.com/L1566/FileGuard/api/proto"
	"google.golang.org/grpc"
)

type Client struct {
	conn   *grpc.ClientConn
	client pb.KeyManagementServiceClient
	cache  sync.Map // key_id -> key_material (optional)
}

func NewClient(addr string) (*Client, error) {
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:   conn,
		client: pb.NewKeyManagementServiceClient(conn),
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// Encrypt 加密数据，返回密文和使用的key_id
func (c *Client) Encrypt(ctx context.Context, plaintext []byte) (ciphertext string, keyID string, err error) {
	// 缓存中存的不再是密钥材料，而是服务端返回的 key_id
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
		// 注意：key_material 只在客户端需要本地加密时才用，这里用不上（加解密都在服务端）
	}
	// 使用服务端返回的 key_id 发起加密请求
	encResp, err := c.client.Encrypt(ctx, &pb.EncryptRequest{
		KeyId:     currentKeyID,
		Plaintext: plaintext,
	})
	if err != nil {
		return "", "", err
	}
	return encResp.Ciphertext, currentKeyID, nil
}

// Decrypt 解密数据
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
