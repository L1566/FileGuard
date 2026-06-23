# FileGuard - 企业 AI 增强文件访问控制系统

[![License](https://img.shields.io/badge/License-AGPL%20V3-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/L1566/FileGuard)](https://goreportcard.com/report/github.com/L1566/FileGuard)

**FileGuard** 是一个面向企业的 AI 增强文件访问控制与防泄露系统，基于零信任思想，提供细粒度的权限管理、动态加密、AI 风险评分、行为审计和终端防护能力。

- **通用性**：适用于制造、金融、研发等任何对敏感文件有保护需求的行业
- **示例场景**：以新能源汽车企业为核心演示背景，展示如何防止设计图纸、电池配方、供应链数据等被盗或外泄

---

## 目录

- [背景与痛点](#背景与痛点)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [配置参考](#配置参考)
- [API 参考](#api-参考)
- [典型策略示例](#典型策略示例)
- [扩展与定制](#扩展与定制)
- [安全与合规](#安全与合规)
- [开发指南](#开发指南)
- [开源协议](#开源协议)

---

## 背景与痛点

传统文件访问控制（如 ACL、NTFS 权限）存在以下问题：
- **静态授权**：权限一旦授予，长期有效，无法应对实时风险
- **内部威胁**：离职员工、恶意管理员可批量窃取文件
- **边界失效**：移动办公、云协作使传统内网隔离形同虚设
- **规则僵化**：人工编写的 DLP 规则无法识别语义级敏感内容

在新能源汽车企业中，典型风险包括：
- 研发人员私自拷贝整车设计图到个人 U 盘
- 离职工程师批量导出自动驾驶核心代码
- 供应商通过协作通道非法留存电池配方文档

FileGuard 通过 **动态授权、AI 风险评分、全链路加密、行为审计** 四大支柱，系统性解决上述问题。

---

## 核心特性

| 特性 | 说明 |
|------|------|
| **🤖 AI 动态风险评分** | 云端 LLM 实时评估访问风险，PII 本地脱敏后发送，动态调整权限（允许/MFA/审批/拒绝） |
| **多因素认证 (MFA)** | 支持 TOTP 双因素认证，bcrypt 密码哈希，JWT 令牌管理 |
| **基于属性的访问控制 (ABAC)** | 动态判定用户属性、文件属性、环境属性（时间/IP/设备），支持正则和列表匹配 |
| **透明加密 + KMS** | 文件存储/传输 AES-256-GCM 加密，gRPC KMS 服务管理密钥生命周期，密钥文件持久化 |
| **数据防泄漏 (DLP)** | 识别敏感内容（关键词/正则），支持 block/alert/log 三种动作，上传/下载双向拦截 + 命中敏感内容强制水印 |
| **数字水印** | 图片（gg 库渲染）和文本文件添加用户/时间水印，字体路径可配置 |
| **全行为审计** | JSON 行格式审计日志，记录完整决策链（含风险评分），支持文件追加 |
| **零信任架构** | 所有访问请求必经安全网关，不信任任何内网/外网环境，ABAC + AI 双重决策 |
| **终端代理** | fsnotify 递归目录监控，文件事件 + 心跳上报至网关 |
| **容器化部署** | 多阶段 Docker 构建，docker-compose 编排，Kubernetes 部署清单 |

---

## 系统架构

```
┌──────────┐     ┌────────────────┐      ┌──────────────┐     ┌─────────────┐
│  Client  │────▶│    Gateway     │────▶│ Risk Service │────▶│  Cloud LLM  │
│          │     │  (零信任网关)    │      │  (AI 评分)   │      │  (Claude)   │
└──────────┘     │                │      └──────────────┘     └─────────────┘
                 │ ABAC + DLP     │
                 │ 加密/解密       │     ┌──────────────┐
                 │ 水印 + 审计     │────▶│     KMS      │
                 │ JWT + MFA      │     │  (密钥管理)   │
                 └────────────────┘     └──────────────┘
                        │
                        ▼
                 ┌────────────────┐     ┌──────────────┐
                 │   Storage      │     │    Agent     │
                 │ (本地/S3/MinIO) │     │  (终端监控)   │
                 └────────────────┘     └──────────────┘
```

**核心组件：**
- **Gateway（零信任网关）**：HTTP 服务（`:8080`），所有文件请求必经，集成 JWT 认证、ABAC 评估、DLP 检测、加解密、水印、审计和 AI 风险评分
- **Risk Service（AI 风险评分）**：HTTP 服务（`:8090`），接收网关转发的访问上下文，PII 脱敏后调用 Claude API 进行多维度风险评分，支持缓存和降级
- **KMS（密钥管理服务）**：gRPC 服务（`:50051`），管理 AES 密钥的生成、加密、解密、轮换、吊销，密钥 JSON 文件持久化
- **Agent（终端代理）**：fsnotify 监控目录变化，POST 事件和心跳到网关
- **Audit Service（审计服务）**：`:8082`，审计日志查询与管理
- **Policy Service（策略服务）**：`:8081`，集中策略管理与分发

---

## 快速开始

### 环境要求

- Go 1.25+
- Docker & Docker Compose（可选）
- 4GB RAM，2 CPU

### 方式一：源码运行

```bash
# 克隆仓库
git clone https://github.com/L1566/FileGuard.git
cd FileGuard

# 安装依赖
go mod download

# 构建所有服务
make build
# 二进制文件输出到 bin/ 目录

# 启动 KMS（密钥管理）
make run-kms

# 启动网关（另一个终端）
make run-gateway

# （可选）启动 AI 风险评分服务
export FILEGUARD_LLM_API_KEY="sk-ant-..."  # Claude API Key
make run-riskservice

# （可选）启动终端代理
make run-agent
```

### 方式二：Docker Compose

```bash
cd FileGuard
docker-compose up -d
# 启动 gateway + kms 两个服务
```

### 默认端口

| 服务 | 端口 | 协议 |
|------|:----:|------|
| Gateway | 8080 | HTTP |
| KMS | 50051 | gRPC |
| Risk Service | 8090 | HTTP |
| Audit Service | 8082 | HTTP |
| Policy Service | 8081 | HTTP |
| Agent | 8084 | HTTP |

---

## 使用说明

### 1. 认证与登录

```bash
# 登录获取 JWT Token
curl -X POST http://localhost:8080/api/auth/login \
	-H "Content-Type: application/json" \
    -d '{"username": "alice", "password": "password123"}'

# 响应
# {"success": true, "data": {"token": "eyJhbGciOi..."}}

# 设置 MFA（双因素认证）
TOKEN="<从登录响应获取的token>"
curl -X POST http://localhost:8080/api/auth/setup-mfa \
-H "Authorization: Bearer $TOKEN"
# 返回 secret 和 qrcode_url，用 Google Authenticator 扫描

# 验证并启用 MFA
curl -X POST http://localhost:8080/api/auth/verify-mfa \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d '{"passcode": "123456"}'
```

**测试账户：**

| 用户名 | 密码 | 角色 | 项目 |
|--------|------|------|------|
| alice | password123 | engineer | ev_project |
| admin | admin123 | admin | - |

### 2. 文件上传与下载

```bash
TOKEN="<JWT Token>"

# 上传文件（自动 AES-256-GCM 加密存储）
curl -X PUT http://localhost:8080/file/projects/battery_spec.xlsx \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @battery_spec.xlsx

# 下载文件（自动解密）
curl -X GET http://localhost:8080/file/projects/battery_spec.xlsx \
  -H "Authorization: Bearer $TOKEN" \
  -o downloaded.xlsx
```

> **访问控制流程：** JWT 认证 → ABAC 策略评估 → AI 风险评分 → DLP 检测 → 加密/解密 → 水印（如需）→ 审计记录

### 3. AI 风险评分（可选）

启用 AI 风险评分后，Gateway 在 ABAC 通过后会额外调用 Risk Service 进行实时评估：

```bash
# 1. 设置 Claude API Key
export FILEGUARD_LLM_API_KEY="sk-ant-api03-..."

# 2. 编辑 configs/gateway.yaml，启用 risk
# risk:
#   enabled: true
#   mode: shadow  # shadow → monitor → active

# 3. 启动 Risk Service
go run ./cmd/riskservice -config configs/riskservice.yaml

# 4. 启动 Gateway（自动连接 Risk Service）
go run ./cmd/gateway -config configs/gateway.yaml
```

**渐进上线模式：**（由 `risk.mode` 控制，运行时按模式分流决策）

| 模式 | 行为 | 风险 |
|------|------|------|
| `shadow` | AI 评分仅记录到审计日志（`risk_score`/`risk_level`/`risk_action`/`risk_mode`），完全不影响放行决策 | 零 |
| `monitor` | 低/中风险记录 step-up 建议；高风险**保留 ABAC 决策**（审计标记 `risk_would_deny`，不硬拒绝） | 低 |
| `active` | 全量执行 AI + ABAC 混合决策，`deny` 动作直接返回 403 并告警 | 可控 |

> 未配置 `mode` 时默认 `shadow`，确保新接入风险评分时零业务影响。

**风险评分 → 动作映射：**

| 评分范围 | 风险等级 | 动作 |
|----------|----------|------|
| 0.0–0.3 | low | 直接允许 |
| 0.3–0.6 | medium | 触发 Step-up MFA |
| 0.6–0.8 | high | 要求主管审批 |
| 0.8–1.0 | critical | 拒绝 + 告警 |

**降级策略（`risk.fallback`）：** 当 Risk Service 超时或不可用时，Gateway 按此策略处理（审计记录 `risk_degraded=true`）：

| 取值 | 行为 |
|------|------|
| `allow` | 保留 ABAC 决策放行（默认，可用性优先） |
| `abac_only` | 同 `allow`，仅以 ABAC 结果为准 |
| `deny` | 直接拒绝（安全优先，返回 403） |

### 4. 策略管理

```bash
TOKEN="<JWT Token>"

# 查看所有规则
curl http://localhost:8080/api/policy/rules \
  -H "Authorization: Bearer $TOKEN"

# 添加新规则
curl -X POST http://localhost:8080/api/policy/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block_interns_confidential",
    "effect": "deny",
    "conditions": {
      "user.role": "intern",
      "resource.sensitivity": "confidential"
    }
  }'

# 更新规则
curl -X PUT http://localhost:8080/api/policy/rules/block_interns_confidential \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{...}'

# 删除规则
curl -X DELETE http://localhost:8080/api/policy/rules/block_interns_confidential \
  -H "Authorization: Bearer $TOKEN"
```

> 策略文件 `configs/rules.json` 支持热加载（fsnotify 监听），修改后自动生效。

### 5. 终端代理

```bash
# 编辑 configs/agent.yaml 配置监控目录和网关地址
# monitor:
#   root_dir: /path/to/watch

# 启动代理
go run ./cmd/agent -config configs/agent.yaml

# 代理自动监控目录变化并上报至网关
# 事件端点: POST /api/agent/event
# 心跳端点: POST /api/agent/heartbeat
```

### 6. 健康检查

```bash
# Gateway
curl http://localhost:8080/health

# Risk Service
curl http://localhost:8090/health
# {"status": "ok", "degraded": false}

# KMS（gRPC，使用 grpcurl）
grpcurl -plaintext localhost:50051 list
```

---

## 配置参考

### Gateway (`configs/gateway.yaml`)

```yaml
service:
  name: FileGuard-gateway
  port: 8080

jwt:
  secret_key: "your-256-bit-secret-key-change-in-production"
  issuer: "FileGuard"
  expiry: 24h

storage:
  type: local          # local | s3（待实现）
  root_dir: ./data

policy:
  rules_file: ./configs/rules.json

audit:
  log_file: ./logs/audit.log

kms:
  address: localhost:50051

dlp:
  rules_file: ./configs/dlp_rules.json

watermark:
  font_path: ./fonts/1_Minecraft-Regular.otf

risk:                 # AI 风险评分（可选）
  enabled: true
  mode: shadow        # shadow | monitor | active
  service_url: http://localhost:8090
  cache_ttl: 5m
  timeout: 500ms
  fallback: allow     # allow | deny | abac_only
```

### Risk Service (`configs/riskservice.yaml`)

```yaml
service:
  name: FileGuard-riskservice
  port: 8090

log:
  level: info
  format: text

llm:
  provider: anthropic
  model: claude-sonnet-4-6
  api_key_env: FILEGUARD_LLM_API_KEY
  timeout: 10s
  max_retries: 2

cache:
  max_entries: 10000
  ttl: 5m
```

### KMS (`configs/kms.yaml`)

```yaml
service:
  name: FileGuard-kms
  port: 50051

key_store:
  file: ./data/kms/keys.json  # 密钥持久化文件
```

---

## API 参考

### 公开端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/api/auth/login` | 用户登录（返回 JWT） |

### JWT 保护的端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth/setup-mfa` | 生成 TOTP 密钥和二维码 |
| POST | `/api/auth/verify-mfa` | 验证并启用 MFA |
| GET | `/api/policy/rules` | 列出所有 ABAC 规则 |
| POST | `/api/policy/rules` | 添加规则 |
| PUT | `/api/policy/rules/{id}` | 更新规则 |
| DELETE | `/api/policy/rules/{id}` | 删除规则 |
| POST | `/api/agent/event` | 接收终端文件事件 |
| POST | `/api/agent/heartbeat` | 接收终端心跳 |
| GET | `/file/{path}` | 下载文件（经完整访问控制链） |
| PUT | `/file/{path}` | 上传文件（经完整访问控制链） |

### Risk Service 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查（含降级状态） |
| POST | `/api/risk/evaluate` | 执行风险评分 |

### KMS gRPC 服务

| RPC | 说明 |
|-----|------|
| `GenerateKey` | 生成新密钥 |
| `Encrypt` | 加密数据 |
| `Decrypt` | 解密数据 |
| `RotateKey` | 轮换密钥 |
| `RevokeKey` | 吊销密钥 |

---

## 典型策略示例

以新能源汽车企业为背景的 ABAC 规则：

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

DLP 规则示例（`configs/dlp_rules.json`）：

```json
[
  {
    "id": "dlp_credit_card",
    "name": "信用卡号",
    "pattern": "\\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\\b",
    "is_regex": true,
    "sensitivity": "critical",
    "action": "block",
    "enabled": true
  },
  {
    "id": "dlp_battery_params",
    "name": "电池参数",
    "pattern": "battery.*capacity|voltage.*range",
    "is_regex": true,
    "sensitivity": "high",
    "action": "alert",
    "enabled": true
  },
  {
    "id": "dlp_confidential",
    "name": "机密关键词",
    "pattern": "CONFIDENTIAL",
    "is_regex": false,
    "sensitivity": "medium",
    "action": "alert",
    "enabled": true
  }
]
```

**DLP 动作语义：**

| `action` | 上传 (PUT) | 下载 (GET) | 审计字段 |
|----------|-----------|-----------|----------|
| `block` | 拒绝上传（403） | 拒绝下载（403） | `dlp_action=block` |
| `alert` | 放行并告警（warn 日志） | 放行并告警 | `dlp_action=alert` |
| `log` | 放行并记录（info 日志） | 放行并记录 | `dlp_action=log` |

> 此外，命中 `sensitivity=critical` 且非 `block` 的规则时，下载会**强制添加水印**（即使原 ABAC 策略未要求）。命中详情均通过 `mergeDetails` 合并写入审计 `details`，不覆盖风险评分等其它字段。

---

## 扩展与定制

FileGuard 设计为高度可插拔：

- **策略引擎插件**：实现自定义属性（如项目代号、设备安全评分）
- **存储适配器**：本地文件系统（已实现）、S3/MinIO（占位，待实现）、阿里云 OSS
- **身份源集成**：LDAP、OAuth2、企业微信、钉钉、飞书
- **DLP 规则引擎**：可配置关键词、正则（已实现）、机器学习分类器（规划中）
- **审计后端**：文件日志（已实现）、Elasticsearch、Splunk、区块链存证（规划中）
- **AI 模型**：当前支持 Anthropic Claude API，可扩展至 OpenAI、本地 Ollama 模型

---

## 安全与合规

- **等保 2.0 三级**：满足身份鉴别、访问控制、安全审计等要求
- **密码安全**：bcrypt 哈希存储，常量时间比较
- **密钥安全**：AES-256-GCM 加密，密钥文件 0600 权限，环境变量注入 API Key
- **PII 保护**：AI 风险评分前本地正则脱敏，敏感数据不出网
- **日志防篡改**：JSON 行格式审计日志，记录完整决策链
- **GDPR / 个人信息保护法**：支持文件内容脱敏（自动遮盖身份证、手机号等）

详见 [SECURITY.md](SECURITY.md) 完整安全测试清单。

---

## 开发指南

### 项目结构

```
cmd/              # 服务入口（gateway, kms, agent, riskservice, audit, policy）
internal/         # 私有应用包（handler, middleware, server, monitor, reporter）
pkg/              # 公共库
  abac/           # ABAC 策略引擎
  audit/          # 审计日志
  auth/           # JWT + MFA
  config/         # 配置加载
  crypto/         # AES/RSA 加解密
  dlp/            # DLP 检测引擎
  kms/            # KMS gRPC 客户端
  risk/           # AI 风险评分（类型、脱敏、评分、提示词、客户端）
  storage/        # 存储接口与实现
  watermark/      # 图片/文本水印
configs/          # 配置文件
deployments/      # Docker + Kubernetes
test/integration/ # 集成测试
docs/             # 文档与设计规格
```

### 常用命令

```bash
make build          # 构建全部 6 个二进制
make test           # 运行全部测试（含覆盖率）
make lint           # 静态分析（golangci-lint）
make run-gateway    # 启动网关
make run-kms        # 启动 KMS
make run-agent      # 启动终端代理
make run-riskservice # 启动 AI 风险评分
make clean          # 清理构建产物
```

构建脚本（含版本注入）：
```bash
./scripts/build.sh v2.0.0    # 构建全部二进制 + 版本标记
./scripts/test.sh ./pkg/...  # 运行测试 + 生成 HTML 覆盖率报告
```

### 运行测试

```bash
# 全部测试
go test -race -count=1 ./...

# 仅 AI 风险评分包
go test -race -v ./pkg/risk/...

# 集成测试
go test -race -v ./test/integration/...
```

---

## 开源协议

AGPL v3。详见 [LICENSE](LICENSE) 文件。

---

**FileGuard — 让每个文件都在 AI 守护之下**
