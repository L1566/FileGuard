# =============================================================================
# FileGuard 网关 — 多阶段构建
# =============================================================================
# 构建: docker build -f deployments/docker/Dockerfile -t fileguard-gateway .
# 运行: docker run -p 8080:8080 -v $(pwd)/configs:/app/configs -v $(pwd)/data:/app/data fileguard-gateway

# ---- 阶段 1: 编译 ----
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/gateway ./cmd/gateway
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/kms ./cmd/kms
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/agent ./cmd/agent

# ---- 阶段 2: 运行 ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -g '' fileguard

COPY --from=builder /bin/gateway /bin/kms /bin/agent /usr/local/bin/
COPY --from=builder /src/configs /app/configs
COPY --from=builder /src/fonts /app/fonts

RUN mkdir -p /app/data /app/logs && chown -R fileguard:fileguard /app

USER fileguard
WORKDIR /app

# 默认启动网关；覆盖 CMD 可切换为 kms 或 agent
CMD ["gateway", "-config", "configs/gateway.yaml"]
