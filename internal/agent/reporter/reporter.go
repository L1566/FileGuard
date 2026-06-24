package reporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/L1566/FileGuard/internal/agent/monitor"
	"github.com/L1566/FileGuard/pkg/config"
	"github.com/L1566/FileGuard/pkg/logger"
)

type Config struct {
	GatewayURL   string
	HeartbeatInt time.Duration
	ClientID     string
	TLSConfig    *config.TLSSettings // 可选 TLS 配置
}

type Reporter struct {
	cfg    Config
	client *http.Client
	events <-chan monitor.FileEvent
	done   chan struct{}
}

func NewReporter(cfg Config, events <-chan monitor.FileEvent) *Reporter {
	r := &Reporter{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		events: events,
		done:   make(chan struct{}),
	}
	if cfg.TLSConfig != nil && cfg.TLSConfig.Enabled {
		tlsCfg := &tls.Config{}
		if cfg.TLSConfig.CAFile != "" {
			caCert, err := os.ReadFile(cfg.TLSConfig.CAFile)
			if err == nil {
				caPool := x509.NewCertPool()
				caPool.AppendCertsFromPEM(caCert)
				tlsCfg.RootCAs = caPool
			}
		}
		r.client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	return r
}

func (r *Reporter) Start(ctx context.Context) {
	// 上报事件
	go func() {
		for {
			select {
			case ev := <-r.events:
				r.reportEvent(ev)
			case <-ctx.Done():
				r.Stop()
				return
			case <-r.done:
				return
			}
		}
	}()
	// 心跳
	go r.heartbeat(ctx)
}

func (r *Reporter) reportEvent(ev monitor.FileEvent) {
	payload := map[string]interface{}{
		"client_id": r.cfg.ClientID,
		"event":     ev,
		"timestamp": time.Now().Unix(),
	}
	data, _ := json.Marshal(payload)
	resp, err := r.client.Post(r.cfg.GatewayURL+"/api/agent/event", "application/json", bytes.NewReader(data))
	if err != nil {
		logger.Errorf("Failed to report event: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Warnf("Gateway returned non-200: %d", resp.StatusCode)
	}
}

func (r *Reporter) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.HeartbeatInt)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.sendHeartbeat()
		case <-ctx.Done():
			return
		case <-r.done:
			return
		}
	}
}

func (r *Reporter) sendHeartbeat() {
	payload := map[string]string{"client_id": r.cfg.ClientID}
	data, _ := json.Marshal(payload)
	resp, err := r.client.Post(r.cfg.GatewayURL+"/api/agent/heartbeat", "application/json", bytes.NewReader(data))
	if err != nil {
		logger.Debugf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (r *Reporter) Stop() {
	close(r.done)
}
