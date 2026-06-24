package risk

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/L1566/FileGuard/pkg/config"
)

// Client Gateway 侧 Risk Service 调用客户端
type Client struct {
	serviceURL string
	httpClient *http.Client
}

// NewClient 创建风险评分客户端。tlsCfg 为 nil 或 Enabled=false 时使用明文 HTTP。
func NewClient(serviceURL string, timeout time.Duration, tlsCfg *config.TLSSettings) *Client {
	c := &Client{
		serviceURL: serviceURL,
		httpClient: &http.Client{Timeout: timeout},
	}
	if tlsCfg != nil && tlsCfg.Enabled {
		transport := &http.Transport{
			TLSClientConfig: buildTLSConfig(tlsCfg),
		}
		c.httpClient.Transport = transport
	}
	return c
}

func buildTLSConfig(cfg *config.TLSSettings) *tls.Config {
	tlsCfg := &tls.Config{}
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return tlsCfg
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caCert)
		tlsCfg.RootCAs = caPool
	}
	return tlsCfg
}

// Evaluate 向 Risk Service 发起评分请求
func (c *Client) Evaluate(ctx context.Context, req *EvaluateRequest) (*EvaluateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.serviceURL+"/api/risk/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("risk service call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("risk service returned %d", resp.StatusCode)
	}

	var result EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &result, nil
}
