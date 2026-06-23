#!/usr/bin/env bash
# FileGuard 构建脚本
# 用法: ./scripts/build.sh [版本号]
set -euo pipefail

VERSION="${1:-dev}"
BINARY_DIR="bin"
LDFLAGS="-s -w -X main.Version=${VERSION}"

echo "==> Building FileGuard ${VERSION}..."

mkdir -p "${BINARY_DIR}"

# 构建所有服务
echo "  -> gateway"
go build -ldflags="${LDFLAGS}" -o "${BINARY_DIR}/gateway" ./cmd/gateway

echo "  -> kms"
go build -ldflags="${LDFLAGS}" -o "${BINARY_DIR}/kms" ./cmd/kms

echo "  -> agent"
go build -ldflags="${LDFLAGS}" -o "${BINARY_DIR}/agent" ./cmd/agent

echo "  -> audit"
go build -ldflags="${LDFLAGS}" -o "${BINARY_DIR}/audit" ./cmd/audit

echo "  -> policy"
go build -ldflags="${LDFLAGS}" -o "${BINARY_DIR}/policy" ./cmd/policy

echo ""
echo "==> Build complete:"
ls -lh "${BINARY_DIR}/"
