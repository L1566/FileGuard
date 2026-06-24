#!/bin/bash
# 生成 KMS gRPC TLS 开发环境自签名证书
# 生产环境请使用正式 CA 签发的证书

set -e

CERT_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERT_DIR"

echo "=== 生成 CA 根证书 ==="
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca.pem" \
  -subj "/CN=FileGuard CA/O=FileGuard Dev"

echo "=== 生成 KMS 服务端证书 ==="
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/kms-key.pem" -out "$CERT_DIR/kms-req.pem" \
  -subj "/CN=localhost/O=FileGuard KMS" \
  -addext "subjectAltName=DNS:localhost,DNS:kms,IP:127.0.0.1"

openssl x509 -req -in "$CERT_DIR/kms-req.pem" -days 365 \
  -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial \
  -out "$CERT_DIR/kms-cert.pem" \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:kms,IP:127.0.0.1")

echo "=== 生成 Risk Service 服务端证书 ==="
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/riskservice-key.pem" -out "$CERT_DIR/riskservice-req.pem" \
  -subj "/CN=localhost/O=FileGuard RiskService" \
  -addext "subjectAltName=DNS:localhost,DNS:riskservice,IP:127.0.0.1"

openssl x509 -req -in "$CERT_DIR/riskservice-req.pem" -days 365 \
  -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial \
  -out "$CERT_DIR/riskservice-cert.pem" \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:riskservice,IP:127.0.0.1")

echo "=== 生成 Gateway 服务端证书 ==="
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/gateway-key.pem" -out "$CERT_DIR/gateway-req.pem" \
  -subj "/CN=localhost/O=FileGuard Gateway" \
  -addext "subjectAltName=DNS:localhost,DNS:gateway,IP:127.0.0.1"

openssl x509 -req -in "$CERT_DIR/gateway-req.pem" -days 365 \
  -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial \
  -out "$CERT_DIR/gateway-cert.pem" \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:gateway,IP:127.0.0.1")

# 删除临时文件
rm -f "$CERT_DIR/kms-req.pem" "$CERT_DIR/riskservice-req.pem" "$CERT_DIR/gateway-req.pem"

echo "=== 证书生成完成 ==="
echo "CA:                $CERT_DIR/ca.pem"
echo "KMS cert:          $CERT_DIR/kms-cert.pem"
echo "KMS key:           $CERT_DIR/kms-key.pem"
echo "RiskService cert:  $CERT_DIR/riskservice-cert.pem"
echo "RiskService key:   $CERT_DIR/riskservice-key.pem"
echo "Gateway cert:      $CERT_DIR/gateway-cert.pem"
echo "Gateway key:       $CERT_DIR/gateway-key.pem"
echo ""
echo "启用 TLS 步骤:"
echo "1. 设置 configs/kms.yaml:        tls.enabled: true"
echo "2. 设置 configs/gateway.yaml:     tls.enabled: true + kms.tls.enabled: true + risk.tls.enabled: true"
echo "3. 设置 configs/riskservice.yaml: tls.enabled: true"
echo "4. 设置 configs/agent.yaml:       gateway.tls.enabled: true"
