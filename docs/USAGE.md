# FileGuard 使用说明与配置规范

## 目录

- [1. 项目概述](#1-项目概述)
- [2. 系统要求](#2-系统要求)
- [3. 快速开始](#3-快速开始)
- [4. 服务启动顺序与依赖](#4-服务启动顺序与依赖)
- [5. 配置文件参考](#5-配置文件参考)
  - [5.1 Gateway (`configs/gateway.yaml`)](#51-gateway-configsgatewayyaml)
  - [5.2 KMS (`configs/kms.yaml`)](#52-kms-configskmsyaml)
  - [5.3 Risk Service (`configs/riskservice.yaml`)](#53-risk-service-configsriskserviceyaml)
  - [5.4 Audit (`configs/audit.yaml`)](#54-audit-configsaudityaml)
  - [5.5 Policy (`configs/policy.yaml`)](#55-policy-configspolicyyaml)
  - [5.6 Agent (`configs/agent.yaml`)](#56-agent-configsagentyaml)
- [6. API 参考](#6-api-参考)
  - [6.1 公开端点](#61-公开端点)
  - [6.2 JWT 保护端点](#62-jwt-保护端点)
  - [6.3 文件访问端点](#63-文件访问端点)
  - [6.4 Risk Service 端点](#64-risk-service-端点)
- [7. gRPC 服务参考](#7-grpc-服务参考)
  - [7.1 KMS（`:50051`）](#71-kms50051)
  - [7.2 Audit（`:8082`）](#72-audit8082)
  - [7.3 Policy（`:8081`）](#73-policy8081)
- [8. TLS 传输加密](#8-tls-传输加密)
- [9. 本地 LLM 模型部署](#9-本地-llm-模型部署)
- [10. DLP 规则配置](#10-dlp-规则配置)
- [11. ABAC 策略规则配置](#11-abac-策略规则配置)
- [12. Docker 部署](#12-docker-部署)
- [13. 健康检查](#13-健康检查)
- [14. 环境变量参考](#14-环境变量参考)
- [15. Make 命令参考](#15-make-命令参考)
- [16. 故障排查](#16-故障排查)

---

## 1. 项目概述

FileGuard 是一个企业 AI 增强文件访问控制系统，包含 **6 个微服务**：

| 服务 | 端口 | 协议 | 说明 |
|------|:----:|------|------|
| **Gateway** | 8080 | HTTP/HTTPS | 零信任网关：认证、授权、加密、DLP、水印、审计 |
| **KMS** | 50051 | gRPC | 密钥管理：AES-256-GCM 加解密及密钥生命周期 |
| **Risk Service** | 8090 | HTTP/HTTPS | AI 风险评分：7 种 LLM 后端支持 |
| **Audit** | 8082 | gRPC | 审计日志：持久化、查询 |
| **Policy** | 8081 | gRPC | 策略引擎：ABAC 规则管理 |
| **Agent** | — | HTTP/HTTPS 客户端 | 终端代理：文件监控 + 心跳上报（**纯客户端，不监听端口**） |

**访问控制流程：**

```
请求 → JWT 认证 → ABAC 策略评估 → AI 风险评分 → DLP 检测 → 加密/解密 → 水印 → 审计记录
```

---

## 2. 系统要求

| 项目 | 要求 |
|------|------|
| Go | 1.25+ |
| 操作系统 | Linux / Windows |
| 内存 | 建议 ≥ 4GB（含本地 LLM 时 ≥ 32GB） |
| CPU | ≥ 2 核 |
| GPU | ≥ 32GB（本地 LLM 时） |
| 可选 | Docker & Docker Compose |
| 可选 | OpenSSL（用于 TLS 证书生成） |
| 可选 | Make（用于快捷构建命令） |

---

## 3. 快速开始

### 3.1 克隆与依赖

```bash
git clone https://github.com/L1566/FileGuard.git
cd FileGuard
go mod download
```

### 3.2 构建

```bash
make build          # 构建全部 6 个二进制 → bin/
```

或手动构建：

```bash
go build -o bin/gateway     ./cmd/gateway
go build -o bin/kms         ./cmd/kms
go build -o bin/riskservice ./cmd/riskservice
go build -o bin/audit       ./cmd/audit
go build -o bin/policy      ./cmd/policy
go build -o bin/agent       ./cmd/agent
```

### 3.3 启动服务

**最小启动（3 个服务）：**

```bash
# 终端 1：KMS（密钥管理 — 必须先启动）
make run-kms

# 终端 2：Gateway（网关）
make run-gateway

# 终端 3（可选）：Agent（终端代理）
make run-agent
```

**完整启动（6 个服务）：**

```bash
# 终端 1
make run-kms

# 终端 2
make run-gateway

# 终端 3
make run-riskservice

# 终端 4
make run-audit

# 终端 5
make run-policy

# 终端 6
make run-agent
```

### 3.4 环境变量设置

```bash
# AI 风险评分需要（使用云端 LLM 时）
export FILEGUARD_LLM_API_KEY="sk-ant-api03-..."

# 本地模型无需设置此变量
```

### 3.5 验证运行

```bash
# Gateway 健康检查
curl http://localhost:8080/health
# → {"status":"ok"}

# Risk Service 健康检查
curl http://localhost:8090/health
# → {"status":"ok","degraded":false}

# 登录测试
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
# → {"success":true,"data":{"token":"eyJhbGciOi..."}}
```

---

## 4. 服务启动顺序与依赖

```
KMS ────────────── 最先启动（Gateway / Risk Service 依赖）
  │
  ├── Gateway ───── 第二启动（Agent 依赖）
  │     │
  │     └── Agent ─ 最后启动
  │
  ├── Risk Service ─ 独立启动（Gateway 通过 HTTP 调用）
  │
  ├── Audit ─────── 独立启动（Gateway 直写本地审计日志，备选 gRPC）
  │
  └── Policy ────── 独立启动（Gateway 内嵌 ABAC 引擎，备选 gRPC）
```

> **注意**：
> - Gateway **必须**能连接到 KMS，否则启动失败（5s 超时）。
> - Gateway 内嵌 ABAC 评估器和审计日志写入器，Audit 和 Policy gRPC 服务为**可选**辅助服务。
> - Agent 上报文件事件到 Gateway，Gateway **必须**先于 Agent 启动。

---

## 5. 配置文件参考

所有配置文件位于 `configs/` 目录，格式为 YAML。环境变量可通过 `FILEGUARD_` 前缀覆盖配置项（如 `FILEGUARD_KMS_ADDRESS=kms:50051` 覆盖 `kms.address`）。

---

### 5.1 Gateway (`configs/gateway.yaml`)

Gateway 是系统的核心，集成了认证、授权、加密、DLP、水印、审计等全部功能。

```yaml
# ========== 服务基础信息 ==========
service:
  name: FileGuard-gateway       # string   — 服务显示名称
  port: 8080                    # int      — HTTP 监听端口

# ========== Gateway 自身 TLS ==========
tls:
  enabled: false                # bool     — 是否启用 HTTPS（Agent / 客户端连接）
  cert_file: ./certs/gateway-cert.pem  # string — TLS 证书文件路径
  key_file: ./certs/gateway-key.pem    # string — TLS 私钥文件路径

# ========== JWT 认证 ==========
jwt:
  secret_key: "your-256-bit-secret-key-change-in-production"  # string — JWT 签名密钥（≥256 bit）
  issuer: "FileGuard"           # string   — JWT 签发者标识
  expiry: 24h                   # duration — JWT 过期时间（例如 24h / 1h / 30m）

# ========== 日志 ==========
log:
  level: info                   # string   — 日志级别：debug | info | warn | error
  format: text                  # string   — 日志格式：text | json

# ========== 存储 ==========
storage:
  type: local                   # string   — 存储类型：local（S3/MinIO 规划中）
  root_dir: ./data              # string   — 本地存储根目录

# ========== 策略 ==========
policy:
  rules_file: ./configs/rules.json  # string — ABAC 规则文件路径

# ========== 审计 ==========
audit:
  log_file: ./logs/audit.log    # string   — 审计日志文件路径（JSON 行格式）

# ========== KMS 连接 ==========
kms:
  address: localhost:50051      # string   — KMS gRPC 地址
  tls:
    enabled: false              # bool     — 是否启用 gRPC TLS
    ca_file: ./certs/ca.pem     # string   — CA 证书（自签名证书需要）

# ========== DLP 数据防泄漏 ==========
dlp:
  rules_file: ./configs/dlp_rules.json  # string — DLP 规则文件路径

# ========== 水印 ==========
watermark:
  font_path: ./fonts/1_Minecraft-Regular.otf  # string — 图片水印字体文件路径

# ========== AI 风险评分 ==========
risk:
  enabled: true                 # bool     — 是否启用 AI 风险评分
  mode: shadow                  # string   — 渐进上线模式：shadow | monitor | active
  service_url: http://localhost:8090  # string — Risk Service 地址
  timeout: 15s                  # duration — Risk Service 调用超时
  fallback: allow               # string   — 降级策略：allow | deny | abac_only
  trusted_cidrs: []             # []string — 额外可信 IP 段（私有 IP 自动被视为可信）
  tls:
    enabled: false              # bool     — 是否启用 Risk Service HTTPS 客户端
    ca_file: ./certs/ca.pem     # string   — CA 证书
```

**`risk.mode` 详细说明：**

| 模式 | 行为 | 适用阶段 |
|------|------|----------|
| `shadow` | AI 评分仅记录到审计日志，**不影响放行决策** | 新接入、评估期 |
| `monitor` | 高/中/低风险记录建议；高风险保留 ABAC 决策（不硬拒绝） | 观察期 |
| `active` | 全量执行 AI + ABAC 混合决策，`deny` 直接返回 403 | 生产运行 |

**`risk.fallback` 详细说明：**

| 取值 | Risk Service 不可用时的行为 |
|------|---------------------------|
| `allow` | 保留 ABAC 决策放行（**默认**，可用性优先） |
| `abac_only` | 同 `allow`，仅以 ABAC 结果为准 |
| `deny` | 直接拒绝（安全优先，返回 403） |

---

### 5.2 KMS (`configs/kms.yaml`)

KMS 是密钥管理 gRPC 服务，提供 AES-256-GCM 加解密能力。**必须最先启动**。

```yaml
# ========== 服务基础信息 ==========
service:
  name: FileGuard-kms           # string — 服务显示名称
  port: 50051                   # int    — gRPC 监听端口

# ========== 日志 ==========
log:
  level: debug                  # string — 日志级别：debug | info | warn | error
  format: text                  # string — 日志格式：text | json

# ========== 密钥存储 ==========
key_store:
  file: ./data/kms/keys.json    # string — 密钥持久化文件路径（服务自动创建目录）

# ========== TLS ==========
tls:
  enabled: false                # bool   — 是否启用 gRPC 服务端 TLS
  cert_file: ./certs/kms-cert.pem  # string — TLS 证书文件
  key_file: ./certs/kms-key.pem    # string — TLS 私钥文件
```

---

### 5.3 Risk Service (`configs/riskservice.yaml`)

Risk Service 是 AI 风险评分 HTTP 服务，支持 7 种 LLM 后端。

```yaml
# ========== 服务基础信息 ==========
service:
  name: FileGuard-riskservice   # string — 服务显示名称
  port: 8090                    # int    — HTTP 监听端口

# ========== 日志 ==========
log:
  level: debug                  # string — 日志级别：debug | info | warn | error
  format: text                  # string — 日志格式：text | json

# ========== LLM 配置 ==========
llm:
  # ---- 提供商选择 ----
  provider: deepseek            # string — 提供商：
                                #   anthropic | openai | deepseek | google | groq
                                #   | llamacpp | ollama

  # ---- 模型名称 ----
  model: deepseek-v4-pro        # string — 模型标识：
                                #   云端：claude-sonnet-4-6 / gpt-4 / deepseek-v4-pro 等
                                #   本地：Qwen3.5-9B-Q6_K / qwen3:latest 等
                                #   此字段直接透传到 LLM API

  # ---- API Key 环境变量名 ----
  api_key_env: FILEGUARD_LLM_API_KEY  # string — 读取 API Key 的环境变量
                                #   本地模型（llamacpp/ollama）不需要设置

  # ---- 自定义端点（可选）----
  # endpoint: ""                # string — 留空使用提供商默认端点
                                #   填写则覆盖（用于自托管代理或本地模型）
                                #   示例：http://127.0.0.1:8079/v1/chat/completions

  # ---- 超时与重试 ----
  timeout: 10s                  # duration — 单次 LLM HTTP 请求超时
                                #   云端建议 10-15s，本地 CPU 推理建议 30s+

  max_retries: 2                # int    — LLM 调用失败后的重试次数
                                #   仅对网络错误和 HTTP 5xx 重试
                                #   实际最大尝试次数 = max_retries + 1

# ========== 评分缓存 ==========
cache:
  max_entries: 10000            # int      — 缓存最大条目数（LRU 淘汰）
  ttl: 5m                       # duration — 缓存有效期

# ========== TLS ==========
tls:
  enabled: false                # bool   — 是否启用 HTTPS 服务端
  cert_file: ./certs/riskservice-cert.pem  # string — TLS 证书文件
  key_file: ./certs/riskservice-key.pem    # string — TLS 私钥文件
```

**LLM Provider 默认端点：**

| `provider` | 默认端点 | 需要 API Key |
|------------|----------|:-----------:|
| `anthropic` | `https://api.anthropic.com/v1/messages` | ✅ |
| `openai` | `https://api.openai.com/v1/chat/completions` | ✅ |
| `deepseek` | `https://api.deepseek.com/chat/completions` | ✅ |
| `google` | `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` | ✅ |
| `groq` | `https://api.groq.com/openai/v1/chat/completions` | ✅ |
| `llamacpp` | `http://127.0.0.1:8079/v1/chat/completions` | ❌ |
| `ollama` | `http://127.0.0.1:11434/v1/chat/completions` | ❌ |

> **本地模型原理**：llama.cpp server 和 Ollama 都暴露标准 OpenAI `/v1/chat/completions` 格式 API。FileGuard 通过 `OpenAICompatibleProvider` 统一处理，`noAuth: true` 跳过 API Key 校验。`RequiresAPIKey()` 接口方法确保本地 Provider 返回 `false`。

---

### 5.4 Audit (`configs/audit.yaml`)

Audit 是审计 gRPC 服务，负责接收和查询审计日志。

```yaml
# ========== 服务基础信息 ==========
service:
  name: FileGuard-audit         # string — 服务显示名称
  port: 8082                    # int    — gRPC 监听端口

# ========== 日志 ==========
log:
  level: info                   # string — 日志级别：debug | info | warn | error
  format: text                  # string — 日志格式：text | json

# ========== 存储 ==========
storage:
  log_file: ./logs/audit.log    # string — 审计日志文件路径
```

---

### 5.5 Policy (`configs/policy.yaml`)

Policy 是策略管理 gRPC 服务，提供 ABAC 规则的 CRUD 操作。

```yaml
# ========== 服务基础信息 ==========
service:
  name: FileGuard-policy        # string — 服务显示名称
  port: 8081                    # int    — gRPC 监听端口

# ========== 日志 ==========
log:
  level: info                   # string — 日志级别：debug | info | warn | error
  format: text                  # string — 日志格式：text | json

# ========== 策略 ==========
policy:
  rules_file: ./configs/rules.json  # string — 策略规则文件路径
```

---

### 5.6 Agent (`configs/agent.yaml`)

Agent 是终端文件代理，监控指定目录的文件变化并上报至 Gateway。**Agent 是纯客户端，不监听任何端口**。

```yaml
# ========== 服务基础信息 ==========
service:
  name: FileGuard-agent         # string — 服务显示名称
  port: 8085                    # int    — 预留字段（Agent 不监听端口）

# ========== 日志 ==========
log:
  level: info                   # string — 日志级别：debug | info | warn | error
  format: text                  # string — 日志格式：text | json

# ========== 客户端标识 ==========
client_id: "agent-001"          # string — 客户端唯一标识（上报至 Gateway）

# ========== 监控配置 ==========
monitor:
  root_dir: ./data/monitor      # string — 监控根目录（自动创建，递归监控）

# ========== Gateway 连接 ==========
gateway:
  url: http://localhost:8080    # string    — Gateway 地址
  heartbeat: 30s                # duration  — 心跳上报间隔
  tls:
    enabled: false              # bool      — 是否启用 HTTPS 客户端
    ca_file: ./certs/ca.pem     # string    — CA 证书（自签名证书需要）
```

**Agent 上报的事件类型：**

| 事件 | 说明 |
|------|------|
| `CREATE` | 文件/目录创建 |
| `WRITE` | 文件写入/修改 |
| `REMOVE` | 文件/目录删除 |
| `RENAME` | 文件/目录重命名 |

> Agent 使用 fsnotify 递归监控 `monitor.root_dir` 下所有子目录。新创建的子目录会自动被加入监控。

---

## 6. API 参考

所有响应均遵循统一格式：

```json
// 成功
{"success": true, "data": { ... }}

// 失败
{"success": false, "error": "错误消息"}
```

---

### 6.1 公开端点

以下端点**无需 JWT 认证**：

#### `GET /health`

健康检查。

**响应示例：**
```json
{"success": true, "data": {"status": "ok"}}
```

#### `POST /api/auth/login`

用户登录，返回 JWT Token。

**请求体：**
```json
{
  "username": "alice",
  "password": "password123",
  "passcode": "123456"          // 可选，MFA 启用时必填
}
```

**响应示例：**
```json
{"success": true, "data": {"token": "eyJhbGciOiJIUzI1NiIs..."}}
```

**预置测试账户：**

| 用户名 | 密码 | 角色 | 项目 |
|--------|------|------|------|
| `alice` | `password123` | `engineer` | `ev_project` |
| `admin` | `admin123` | `admin` | — |

#### `POST /api/agent/event`

接收终端文件事件（Agent → Gateway）。

**请求体：**
```json
{
  "client_id": "agent-001",
  "event": {
    "Type": "WRITE",
    "Path": "/data/monitor/secret.txt"
  },
  "timestamp": 1719234567
}
```

#### `POST /api/agent/heartbeat`

接收终端心跳（Agent → Gateway）。

**请求体：**
```json
{
  "client_id": "agent-001"
}
```

---

### 6.2 JWT 保护端点

以下端点需要 `Authorization: Bearer <token>` 请求头。

#### 认证相关

**`POST /api/auth/setup-mfa`** — 生成 TOTP 密钥及二维码。

**响应示例：**
```json
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qrcode_url": "otpauth://totp/FileGuard:alice?secret=JBSWY3DPEHPK3PXP&issuer=FileGuard"
  }
}
```

**`POST /api/auth/verify-mfa`** — 验证 TOTP 验证码并启用 MFA。

**请求体：**
```json
{"passcode": "123456"}
```

#### 策略管理

**`GET /api/policy/rules`** — 获取所有 ABAC 规则。

**`POST /api/policy/rules`** — 添加规则（自动持久化到 `rules_file`）。

**请求体：**
```json
{
  "id": "block_interns_confidential",
  "effect": "deny",
  "conditions": {
    "user.role": "intern",
    "resource.sensitivity": "confidential"
  },
  "restrictions": ["watermark"]
}
```

**`PUT /api/policy/rules/{id}`** — 更新规则。

**`DELETE /api/policy/rules/{id}`** — 删除规则。

> 策略文件通过 fsnotify 热加载。通过 API 修改规则后，Gateway 自动重载（无需重启）。

---

### 6.3 文件访问端点

以下端点需要 JWT 认证，并经过完整访问控制链：**ABAC → AI 风险评分 → DLP → 加密/解密 → 水印 → 审计**。

**`GET /file/{path}`** — 下载/读取文件。

- 自动 KMS 解密
- DLP 检测：命中 `block` 规则 → 403；命中 `critical` → 强制水印
- 策略 `restrictions` 包含 `watermark` → 添加水印

**响应头：**
- `Content-Type` — 自动检测（text/plain、application/json、image/png 等）
- `X-FileGuard-Allowed: true` — 请求通过

**`PUT /file/{path}`** — 上传/写入文件。

- 自动 KMS 加密存储（AES-256-GCM）
- DLP 检测：命中 `block` 规则 → 403 拒收
- 文件元数据记录 `key_id`（用于解密）

**请求：** 原始文件二进制内容（`Content-Type` 任意）。

**响应示例：**
```json
{"success": true, "data": {"message": "uploaded"}}
```

---

### 6.4 Risk Service 端点

#### `GET /health`

健康检查（含降级状态）。

**响应示例：**
```json
{"status": "ok", "degraded": false}
```

> `degraded: true` 表示 LLM 调用连续失败 ≥3 次，已进入降级模式（使用确定性规则评分）。

#### `POST /api/risk/evaluate`

执行风险评分。通常由 Gateway 内部调用，也可直接测试。

**请求体（`risk.EvaluateRequest`）：**
```json
{
  "request_id": "req-001",
  "subject": {
    "id": "alice",
    "role": "engineer",
    "project": "ev_project"
  },
  "resource": {
    "path": "projects/battery_spec.xlsx",
    "sensitivity": "confidential"
  },
  "environment": {
    "time": "2026-06-24T21:30:00+08:00",
    "ip": "10.0.0.55"
  },
  "context": {
    "recent_access_count_1h": 5,
    "unique_files_accessed_1h": 3,
    "is_work_hours": false,
    "is_known_location": true,
    "is_trusted_device": false,
    "content_summary": "电池规格参数"
  }
}
```

**响应体（`risk.EvaluateResponse`）：**
```json
{
  "request_id": "req-001",
  "risk_score": 0.45,
  "risk_level": "medium",
  "factors": {
    "time_anomaly": 0.3,
    "location_anomaly": 0.1,
    "behavior_volume": 0.5,
    "content_sensitivity": 0.7
  },
  "recommendation": "mfa",
  "reason": "非工作时间访问敏感文件，建议启用 MFA",
  "cached": false,
  "model": "deepseek-v4-pro",
  "latency_ms": 234
}
```

**`risk_score` → 动作映射：**

| 评分范围 | 风险等级 | 动作 |
|----------|----------|------|
| 0.0–0.3 | `low` | 直接允许 |
| 0.3–0.6 | `medium` | 触发 Step-up MFA |
| 0.6–0.8 | `high` | 要求主管审批 |
| 0.8–1.0 | `critical` | 拒绝 + 告警 |

---

## 7. gRPC 服务参考

### 7.1 KMS（`:50051`）

**服务名：** `kms.KeyManagementService`

| RPC | 请求 | 响应 | 说明 |
|-----|------|------|------|
| `GenerateKey` | `algorithm` (string), `size` (int32) | `key_id` (string), `key_material` (string, Base64) | 生成密钥 |
| `Encrypt` | `key_id` (string), `plaintext` (bytes) | `ciphertext` (string, Base64) | AES-256-GCM 加密 |
| `Decrypt` | `key_id` (string), `ciphertext` (string, Base64) | `plaintext` (bytes) | AES-256-GCM 解密 |
| `RotateKey` | `key_id` (string) | `new_key_id` (string) | 轮换密钥 |
| `RevokeKey` | `key_id` (string) | `success` (bool) | 吊销密钥 |

**使用示例（grpcurl）：**

```bash
# 列出服务
grpcurl -plaintext localhost:50051 list

# 生成密钥
grpcurl -plaintext -d '{"algorithm":"AES256","size":256}' \
  localhost:50051 kms.KeyManagementService/GenerateKey

# 加密
grpcurl -plaintext -d '{"key_id":"<KEY_ID>","plaintext":"SGVsbG8="}' \
  localhost:50051 kms.KeyManagementService/Encrypt
```

健康检查：
```bash
grpc_health_probe -addr=localhost:50051
```

---

### 7.2 Audit（`:8082`）

**服务名：** `audit.AuditService`

| RPC | 请求 | 响应 | 说明 |
|-----|------|------|------|
| `Log` | `event` (AuditEvent) | `success` (bool), `event_id` (string) | 写入审计事件 |
| `Query` | `subject_id`, `resource_path`, `event_type`, `start_time`, `end_time`, `limit`, `offset` | `events` ([]AuditEvent), `total` (int32) | 分页查询 |
| `StreamLog` | stream `LogRequest` | `received` (int32) | 流式接收（高性能场景） |

**AuditEvent 字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 事件 ID |
| `timestamp` | Timestamp | 时间戳 |
| `event_type` | string | `access` / `download` / `upload` / `delete` / `move` |
| `subject_id` | string | 用户 ID |
| `subject_role` | string | 用户角色 |
| `resource_path` | string | 文件路径 |
| `resource_sensitivity` | string | 文件敏感度 |
| `environment_ip` | string | 客户端 IP |
| `allowed` | bool | 是否放行 |
| `reason` | string | 决策原因 |
| `result` | string | `success` / `failure` |
| `details` | map<string,string> | 扩展详情（risk_score、dlp_action 等） |

---

### 7.3 Policy（`:8081`）

**服务名：** `policy.PolicyService`

| RPC | 请求 | 响应 | 说明 |
|-----|------|------|------|
| `Evaluate` | `subject`, `resource`, `environment` | `decision` (Decision) | 评估 ABAC 策略 |
| `GetRules` | — | `rules` ([]Rule) | 获取所有规则 |
| `AddRule` | `rule` (Rule) | `success`, `rule_id` | 添加规则（自动持久化） |
| `UpdateRule` | `rule_id`, `rule` | `success` | 更新规则 |
| `DeleteRule` | `rule_id` | `success` | 删除规则 |
| `Watch` | — | stream `RuleUpdate` | 监听规则变更（流式推送） |

**Rule 结构：**

```json
{
  "id": "allow_engineer_with_watermark",
  "effect": "allow",
  "conditions": {
    "user.role": "engineer",
    "resource.path": "regex:^projects/.*"
  },
  "restrictions": ["watermark"]
}
```

**Decision 结构：**

```json
{
  "allowed": true,
  "reason": "engineer allowed to access project files",
  "restrictions": ["watermark"]
}
```

> Gateway 内嵌了 ABAC 引擎（`MemoryEvaluator`），可直接本地评估。Policy gRPC 服务提供了外部化的规则管理能力。

---

## 8. TLS 传输加密

### 8.1 生成开发证书

```bash
bash scripts/gen_certs.sh
```

生成产物（位于 `certs/`）：

| 文件 | 用途 |
|------|------|
| `ca.pem` / `ca-key.pem` | CA 根证书和私钥 |
| `kms-cert.pem` / `kms-key.pem` | KMS 服务端证书 |
| `gateway-cert.pem` / `gateway-key.pem` | Gateway 服务端证书 |
| `riskservice-cert.pem` / `riskservice-key.pem` | Risk Service 服务端证书 |

> 所有证书包含 SAN：`DNS:localhost, IP:127.0.0.1`，仅适用于本地开发。生产环境请使用正式 CA 签发的证书。

### 8.2 启用全链路 TLS

| 链路 | 配置文件 | 配置项 | 方向 |
|------|----------|--------|------|
| Gateway Server | `gateway.yaml` | `tls.enabled: true` | Agent/Client → Gateway |
| KMS Server | `kms.yaml` | `tls.enabled: true` | KMS gRPC 服务端 |
| Risk Service Server | `riskservice.yaml` | `tls.enabled: true` | Gateway → Risk Service |
| Gateway → KMS | `gateway.yaml` | `kms.tls.enabled: true` | Gateway gRPC 客户端 |
| Gateway → Risk | `gateway.yaml` | `risk.tls.enabled: true` | Gateway HTTP 客户端 |
| Agent → Gateway | `agent.yaml` | `gateway.tls.enabled: true` | Agent HTTP 客户端 |

> **重要**：服务端和客户端必须**同时**启用 TLS。服务端证书的 SAN 必须覆盖客户端的连接地址。

---

## 9. 本地 LLM 模型部署

### 9.1 llama.cpp

```bash
# 1. 下载并启动 llama-server
llama-server -m ./Qwen3.5-9B-Q6_K.gguf \
  --ctx-size 16384 \
  --port 8079 \
  --n-gpu-layers 35
```

`configs/riskservice.yaml` 配置：

```yaml
llm:
  provider: llamacpp
  model: Qwen3.5-9B-Q6_K
  endpoint: http://127.0.0.1:8079/v1/chat/completions
  api_key_env: FILEGUARD_LLM_API_KEY    # 不会实际校验
  timeout: 30s                           # CPU 推理必须 ≥ 30s
  max_retries: 1
```

### 9.2 Ollama

```bash
# 1. 拉取模型
ollama pull qwen3:latest

# 2. 启动服务（默认监听 :11434）
ollama serve
```

`configs/riskservice.yaml` 配置：

```yaml
llm:
  provider: ollama
  model: qwen3:latest
  endpoint: http://127.0.0.1:11434/v1/chat/completions
  api_key_env: FILEGUARD_LLM_API_KEY    # 不会实际校验
  timeout: 10s                           # GPU 推理 1-5s，可设更短
  max_retries: 1
```

### 9.3 云端 vs 本地对比

| 维度 | 云端（Claude/DeepSeek/OpenAI） | 本地（llamacpp/Ollama） |
|------|-------------------------------|------------------------|
| API Key | **必须**设置 `FILEGUARD_LLM_API_KEY` | **不需要** |
| 网络 | 需要出网访问 | 纯内网 |
| 延迟 | 100-500ms | 1-30s（取决于硬件） |
| `timeout` 建议 | 10-15s | **30s+**（CPU） |
| 数据安全 | 发送至第三方 | **完全本地化** |
| 成本 | 按 token 计费 | 仅硬件 + 电费 |

---

## 10. DLP 规则配置

DLP 规则文件路径由 `gateway.yaml` → `dlp.rules_file` 指定（默认 `configs/dlp_rules.json`）。

### 10.1 规则结构

```json
[
  {
    "id": "dlp_unique_id",              // string — 唯一规则 ID
    "name": "规则显示名称",               // string — 可读名称
    "pattern": "关键词或正则表达式",        // string — 匹配模式
    "is_regex": true,                    // bool   — true=正则，false=纯文本关键词
    "sensitivity": "critical",           // string — 敏感度：critical | high | medium | low
    "action": "block",                   // string — 动作：block | alert | log
    "enabled": true                      // bool   — 是否启用
  }
]
```

### 10.2 动作语义

| `action` | 上传 (PUT) | 下载 (GET) | 审计记录 |
|----------|-----------|-----------|----------|
| `block` | 拒绝上传（403） | 拒绝下载（403） | `dlp_action=block` |
| `alert` | 放行 + warn 日志 | 放行 + warn 日志 | `dlp_action=alert` |
| `log` | 放行 + info 日志 | 放行 + info 日志 | `dlp_action=log` |

### 10.3 特殊规则

- **`sensitivity: critical` + 非 `block` 动作** → 下载时**强制添加水印**（即使策略未要求）
- **命中多个规则** → 所有命中的详情均合并到审计 `details`，不覆盖

### 10.4 示例规则集

```json
[
  {
    "id": "dlp_credit_card",
    "name": "Credit Card Number",
    "pattern": "\\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\\b",
    "is_regex": true,
    "sensitivity": "critical",
    "action": "block",
    "enabled": true
  },
  {
    "id": "dlp_battery_params",
    "name": "Battery Parameters",
    "pattern": "battery.*capacity|voltage.*range",
    "is_regex": true,
    "sensitivity": "high",
    "action": "alert",
    "enabled": true
  },
  {
    "id": "dlp_confidential",
    "name": "Confidential Keyword",
    "pattern": "CONFIDENTIAL",
    "is_regex": false,
    "sensitivity": "medium",
    "action": "alert",
    "enabled": true
  }
]
```

---

## 11. ABAC 策略规则配置

ABAC 规则文件路径由 `gateway.yaml` → `policy.rules_file` 指定（默认 `configs/rules.json`）。

### 11.1 规则结构

```json
{
  "id": "规则唯一标识符",                 // string — 规则 ID
  "effect": "allow",                     // string — 效果：allow | deny
  "conditions": {                        // map    — 条件（AND 逻辑）
    "<属性路径>": "<匹配值>"
  },
  "restrictions": ["watermark"]          // []string — 限制：watermark | no_print | no_export
}
```

### 11.2 支持的属性路径

| 属性路径 | 说明 | 示例值 |
|----------|------|--------|
| `user.id` | 用户 ID | `alice` |
| `user.role` | 用户角色 | `engineer`, `admin` |
| `user.type` | 主体类型 | `user`, `service` |
| `user.project` | 所属项目 | `ev_project` |
| `resource.path` | 资源路径 | `regex:^projects/.*` |
| `resource.type` | 资源类型 | `file`, `folder` |
| `resource.sensitivity` | 资源敏感度 | `confidential`, `internal` |
| `environment.ip` | 客户端 IP | `10.0.0.0/8` |
| `environment.time` | 时间 | 未实现 |
| `environment.device_id` | 设备 ID | 未实现 |

### 11.3 匹配模式

- **精确匹配**：`"user.role": "engineer"` — 等值比较
- **正则匹配**：`"resource.path": "regex:^projects/.*"` — `regex:` 前缀启用正则
- **列表匹配**：`"user.role": "in:engineer,admin"` — `in:` 前缀匹配列表

### 11.4 规则评估逻辑

1. 规则**按数组顺序**逐一评估
2. 每个规则的 conditions 做 **AND** 逻辑
3. **首个匹配**的规则生效，后续规则不再评估
4. 无一匹配时，**默认拒绝**

> 因此 `deny_all` 规则应放在**数组末尾**作为兜底。

### 11.5 示例规则集

```json
[
  {
    "id": "allow_engineer_with_watermark",
    "effect": "allow",
    "conditions": {
      "user.role": "engineer",
      "resource.path": "regex:^projects/.*"
    },
    "restrictions": ["watermark"]
  },
  {
    "id": "allow_admin_all",
    "effect": "allow",
    "conditions": {
      "user.role": "admin"
    },
    "restrictions": []
  },
  {
    "id": "deny_all",
    "effect": "deny",
    "conditions": {}
  }
]
```

---

## 12. Docker 部署

### 12.1 Docker Compose（推荐）

```bash
# 1. 构建并启动全部 6 个服务
docker-compose up -d

# 2. 查看状态
docker-compose ps

# 3. 查看日志
docker-compose logs -f gateway

# 4. 停止
docker-compose down
```

**服务依赖（由 docker-compose 控制）：**

```
KMS (health check)
  ├── Gateway   (depends_on: kms healthy)
  │     └── Agent (depends_on: gateway healthy)
  ├── Risk Service (depends_on: kms healthy)
  ├── Audit        (depends_on: kms healthy)
  └── Policy       (depends_on: kms healthy)
```

### 12.2 手动 Docker 构建

```bash
# 构建镜像
docker build -f deployments/docker/Dockerfile -t fileguard .

# 运行各服务
docker run -p 50051:50051 -v $(pwd)/configs:/app/configs:ro \
  fileguard kms -config configs/kms.yaml

docker run -p 8080:8080 -v $(pwd)/configs:/app/configs:ro \
  -e FILEGUARD_KMS_ADDRESS=kms:50051 \
  fileguard gateway -config configs/gateway.yaml
```

**Dockerfile 说明：**
- **构建阶段**：`golang:1.25-alpine` → 编译 6 个二进制（CGO_ENABLED=0 静态链接）
- **运行阶段**：`alpine:3.21` → 内置 `grpc_health_probe`、`ca-certificates`、`tzdata`
- **默认 CMD**：`gateway`，通过 `command` 覆盖启动其他服务

### 12.3 Kubernetes

```bash
# 部署清单（单文件示例）
kubectl apply -f deployments/kubernetes/deployment.yaml
```

---

## 13. 健康检查

### HTTP 服务

```bash
# Gateway
curl http://localhost:8080/health

# Risk Service（含降级状态）
curl http://localhost:8090/health
# → {"status":"ok","degraded":false}
```

### gRPC 服务

```bash
# KMS — grpc_health_probe
grpc_health_probe -addr=localhost:50051

# Audit — grpcurl
grpcurl -plaintext localhost:8082 list
# → audit.AuditService
# → grpc.health.v1.Health
# → grpc.reflection.v1.ServerReflection

# Policy — grpcurl
grpcurl -plaintext localhost:8081 list
# → policy.PolicyService
# → grpc.reflection.v1.ServerReflection
```

### Docker Compose

```bash
# Docker Compose 内置健康检查
docker-compose ps
# HEALTHCHECK 列显示各服务状态
```

---

## 14. 环境变量参考

所有配置项均可通过环境变量覆盖，规则如下：

| 配置路径 | 环境变量 | 示例 |
|----------|----------|------|
| `kms.address` | `FILEGUARD_KMS_ADDRESS` | `kms:50051` |
| `risk.service_url` | `FILEGUARD_RISK_SERVICE_URL` | `http://riskservice:8090` |
| `gateway.url` | `FILEGUARD_GATEWAY_URL` | `http://gateway:8080` |
| `llm.api_key_env` 指向的变量 | `FILEGUARD_LLM_API_KEY` | `sk-ant-api03-...` |

> 环境变量前缀统一为 `FILEGUARD_`，嵌套键用 `_` 连接（如 `kms.address` → `FILEGUARD_KMS_ADDRESS`）。

---

## 15. Make 命令参考

```bash
make build           # 构建全部 6 个二进制 → bin/
make test            # 运行全部测试（race detector + coverage）
make lint            # 静态分析（golangci-lint）
make run-gateway     # 启动网关（go run）
make run-kms         # 启动 KMS（go run）
make run-riskservice # 启动 AI 风险评分（go run）
make run-audit       # 启动审计服务（go run）
make run-policy      # 启动策略服务（go run）
make run-agent       # 启动终端代理（go run）
make clean           # 清理构建产物
make deps            # 下载依赖 + tidy
```

构建脚本：

```bash
./scripts/build.sh v2.0.0       # 构建全部二进制 + 版本注入
./scripts/test.sh ./pkg/...     # 运行测试 + 生成 HTML 覆盖率报告
./scripts/gen_certs.sh          # 生成 CA + 3 个服务端 TLS 证书
```

---

## 16. 故障排查

### 16.1 Gateway 启动失败：KMS 连接超时

**症状：**
```
KMS gRPC connect to localhost:50051: timed out after 5s (last state: CONNECTING)
```

**原因：** KMS 未启动，或 Windows 上 DNS 解析异常。

**解决：**
1. 确认 KMS 已启动：`make run-kms`（另一个终端）
2. 确认端口监听：`netstat -an | findstr 50051`
3. 如果 KMS 已运行但仍超时，检查防火墙规则

### 16.2 Risk Service：连续失败进入降级模式

**症状：**
```
Risk scorer degraded: 3 consecutive failures
```

**原因：** LLM 调用失败（API Key 无效、网络不通、本地模型未启动）。

**排查：**
1. 查看日志中的具体错误：`LLM call failed (provider: xxx): ...`
2. 云端 LLM：确认 `FILEGUARD_LLM_API_KEY` 已设置且有效
3. 本地 LLM：确认 llama-server / Ollama 正在运行
4. 检查 `endpoint` 端口是否与 LLM 服务一致
5. 本地 CPU 推理：`timeout` 应设为 **30s+**

### 16.3 `make run-agent` 失败：目录不存在

**症状：**
```
Failed to add watch path: GetFileAttributesEx ./data/monitor: The system cannot find the file specified.
```

**解决：** 已内置自动创建。如果仍失败，手动 `mkdir -p ./data/monitor`。

### 16.4 文件下载返回 403

**可能原因（按优先级排查）：**

1. **JWT Token 未提供或已过期** → 重新登录获取 Token
2. **ABAC 策略拒绝** → 检查用户角色和文件路径是否匹配规则
3. **AI 风险评分拒绝**（`risk.mode: active`）→ 检查 Risk Service 状态
4. **DLP 拦截** → 文件内容命中 `action: block` 规则
5. **KMS 解密失败** → 检查 KMS 连接，确认 `key_id` 有效

### 16.5 本地模型响应慢

**症状：** Risk Service 日志显示 LLM 调用超时。

**分析：** LLM 调用使用独立 context（不受 Gateway 超时截断），超时仅由 `llm.timeout` 控制。如果 CPU 推理 9B 模型生成 1024 tokens 需要 > 30s，建议：

1. 增加 `llm.timeout` 到 60s 或更高
2. 减少 `max_tokens`（修改 `pkg/risk/provider_openai.go` 中 `BuildRequest` 的 `"max_tokens": 1024`）
3. 使用 GPU 加速（`--n-gpu-layers 35`）
4. 换用小模型（如 3B/1.5B）

### 16.6 审计日志过大

**解决：** 审计日志为 JSON 行格式，支持 logrotate：

```bash
# /etc/logrotate.d/fileguard
/path/to/logs/audit.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

---

> **FileGuard — 让每个文件都在 AI 守护之下**
