# FileGuard API 参考

## 目录

- [1. 概述](#1-概述)
- [2. Gateway HTTP API](#2-gateway-http-api)
  - [2.1 健康检查](#21-健康检查)
  - [2.2 认证](#22-认证)
  - [2.3 文件操作](#23-文件操作)
  - [2.4 策略管理](#24-策略管理)
  - [2.5 Agent 端点](#25-agent-端点)
- [3. Risk Service HTTP API](#3-risk-service-http-api)
  - [3.1 健康检查](#31-健康检查)
  - [3.2 风险评分](#32-风险评分)
- [4. KMS gRPC API](#4-kms-grpc-api)
- [5. Audit gRPC API](#5-audit-grpc-api)
- [6. Policy gRPC API](#6-policy-grpc-api)
- [7. 错误码速查](#7-错误码速查)

---

## 1. 概述

FileGuard 提供 **HTTP REST**（Gateway、Risk Service）和 **gRPC**（KMS、Audit、Policy）两类 API。

| 服务 | 端口 | 协议 | 认证方式 |
|------|:----:|------|----------|
| Gateway | 8080 | HTTP/HTTPS | JWT Bearer Token（部分端点公开） |
| Risk Service | 8090 | HTTP/HTTPS | 无需认证（内部调用） |
| KMS | 50051 | gRPC | 可选 mTLS |
| Audit | 8082 | gRPC | 无需认证 |
| Policy | 8081 | gRPC | 无需认证 |

### 通用响应格式

所有 HTTP API 使用统一 JSON 响应：

```json
// 成功
{"success": true, "data": { ... }}

// 失败
{"success": false, "error": "错误描述"}
```

### 通用请求头

| 头名称 | 值 | 说明 |
|--------|-----|------|
| `Content-Type` | `application/json` | 请求体为 JSON 时必填 |
| `Authorization` | `Bearer <JWT>` | JWT 保护端点必填 |

---

## 2. Gateway HTTP API

Gateway 监听 `:8080`，提供认证、文件访问、策略管理、Agent 事件接收等全部对外接口。

### 路由分类

```
公开路由（无需 JWT）:
  GET    /health
  POST   /api/auth/login
  POST   /api/agent/event
  POST   /api/agent/heartbeat

JWT 保护路由（Authorization: Bearer <token>）:
  POST   /api/auth/setup-mfa
  POST   /api/auth/verify-mfa
  GET    /api/policy/rules
  POST   /api/policy/rules
  PUT    /api/policy/rules/{id}
  DELETE /api/policy/rules/{id}
  GET    /file/{path}
  PUT    /file/{path}
```

---

### 2.1 健康检查

#### `GET /health`

无需认证。

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "ok"
  }
}
```

**curl 示例：**
```bash
curl http://localhost:8080/health
```

---

### 2.2 认证

#### `POST /api/auth/login`

用户登录，验证密码后返回 JWT Token。如用户已启用 MFA，需同时提供 TOTP 验证码。

**请求体：**
```json
{
  "username": "alice",
  "password": "password123",
  "passcode": "123456"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `username` | string | ✅ | 用户名 |
| `password` | string | ✅ | 密码（明文，服务端 bcrypt 比较） |
| `passcode` | string | 条件 | TOTP 验证码（用户启用 MFA 时必填） |

**响应 200：**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 400 | `invalid request` | 请求体格式错误 |
| 401 | `invalid credentials` | 用户名或密码错误 |
| 401 | `MFA code required` | 用户已启用 MFA 但未提供 passcode |
| 401 | `invalid MFA code` | TOTP 验证码错误 |
| 500 | `login failed` | JWT 生成失败 |

**curl 示例：**
```bash
# 普通登录
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'

# MFA 用户登录
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123","passcode":"123456"}'
```

**预置测试账户：**

| 用户名 | 密码 | 角色 | 项目 |
|--------|------|------|------|
| `alice` | `password123` | `engineer` | `ev_project` |
| `admin` | `admin123` | `admin` | — |

---

#### `POST /api/auth/setup-mfa`

为当前用户生成 TOTP 密钥和二维码 URL。**需要 JWT。**

**响应 200：**
```json
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qrcode_url": "otpauth://totp/FileGuard:alice?secret=JBSWY3DPEHPK3PXP&issuer=FileGuard"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `secret` | string | Base32 TOTP 密钥 |
| `qrcode_url` | string | 标准 `otpauth://` URL（可用 Google Authenticator 扫描） |

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 401 | `unauthorized` | JWT 无效或缺失 |
| 500 | `setup failed` | TOTP 密钥生成失败 |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X POST http://localhost:8080/api/auth/setup-mfa \
  -H "Authorization: Bearer $TOKEN"
```

---

#### `POST /api/auth/verify-mfa`

验证 TOTP 码，成功后启用 MFA。**需要 JWT。**

**请求体：**
```json
{
  "passcode": "123456"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `passcode` | string | ✅ | 6 位 TOTP 验证码 |

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "MFA enabled"
  }
}
```

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 401 | `unauthorized` | JWT 无效或缺失 |
| 400 | `invalid request` | 请求体格式错误 |
| 400 | `invalid passcode` | TOTP 验证码不匹配 |
| 404 | `user not found` | 用户不存在 |
| 500 | `failed to enable MFA` | MFA 启用失败（未先 setup） |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X POST http://localhost:8080/api/auth/verify-mfa \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passcode":"123456"}'
```

**MFA 启用流程：**
1. `POST /api/auth/setup-mfa` → 获取 `secret` 和 `qrcode_url`
2. 用 Google Authenticator 扫描二维码
3. `POST /api/auth/verify-mfa` → 输入 Authenticator 显示的 6 位数字，验证成功后 MFA 生效

---

### 2.3 文件操作

文件端点经过完整访问控制链：**JWT 认证 → ABAC 策略评估 → AI 风险评分 → DLP 检测 → 加密/解密 → 水印 → 审计**。

#### `GET /file/{path}`

下载/读取文件。**需要 JWT。**

**路径参数：**

| 参数 | 说明 |
|------|------|
| `path` | 文件路径（如 `projects/battery_spec.xlsx`），支持嵌套路径 |

**响应 200（成功）：**

返回文件原始内容。自动完成 KMS 解密。

**响应头：**

| 头名称 | 说明 |
|--------|------|
| `Content-Type` | 自动检测（`text/plain`、`application/json`、`image/png`、`application/pdf`、`application/octet-stream`） |
| `X-FileGuard-Allowed` | `true` |

**DLP 强制水印规则：**

命中 `sensitivity: critical` 且 action 非 `block` 的 DLP 规则时，下载内容**自动添加水印**。

**ABAC 策略 `restrictions` 包含 `watermark` 时**，下载内容自动添加水印。

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 401 | `unauthorized` | JWT 无效或缺失 |
| 400 | `missing file path` | 未提供文件路径 |
| 403 | `<ABAC reason>` | ABAC 策略拒绝 |
| 403 | `risk score too high: ...` | AI 风险评分拒绝（`risk.mode: active`） |
| 403 | `DLP blocked download: ...` | 文件内容命中 DLP `block` 规则 |
| 404 | `file not found` | 文件不存在 |
| 500 | `policy evaluation failed` | ABAC 评估异常 |
| 500 | `failed to read file` | 存储读取失败 |
| 500 | `failed to decrypt file` | KMS 解密失败 |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X GET http://localhost:8080/file/projects/battery_spec.xlsx \
  -H "Authorization: Bearer $TOKEN" \
  -o downloaded.xlsx
```

---

#### `PUT /file/{path}`

上传/写入文件。**需要 JWT。**

**路径参数：**

| 参数 | 说明 |
|------|------|
| `path` | 文件路径（如 `projects/battery_spec.xlsx`），支持嵌套路径 |

**请求体：** 原始文件二进制内容（任意 `Content-Type`）。

**响应 200：**
```json
{
  "success": true,
  "data": {
    "message": "uploaded"
  }
}
```

**行为说明：**
- 自动 AES-256-GCM 加密存储（KMS 可用时）
- KMS 不可用时明文存储（审计记录 `encrypted: false`）
- 文件元数据记录 `key_id`（用于后续解密）

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 401 | `unauthorized` | JWT 无效或缺失 |
| 400 | `missing file path` | 未提供文件路径 |
| 403 | `<ABAC reason>` | ABAC 策略拒绝 |
| 403 | `risk score too high: ...` | AI 风险评分拒绝 |
| 403 | `DLP blocked: ...` | 文件内容命中 DLP `block` 规则 |
| 500 | `policy evaluation failed` | ABAC 评估异常 |
| 500 | `failed to read file content` | 请求体读取失败 |
| 500 | `failed to encrypt file` | KMS 加密失败 |
| 500 | `failed to save file` | 存储写入失败 |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X PUT http://localhost:8080/file/projects/battery_spec.xlsx \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @battery_spec.xlsx
```

---

### 2.4 策略管理

策略管理端点提供 ABAC 规则的 CRUD 操作。所有修改自动持久化到 `configs/rules.json`，Gateway 通过 fsnotify 热加载。**需要 JWT。**

#### `GET /api/policy/rules`

获取所有 ABAC 规则列表。

**响应 200：**
```json
{
  "success": true,
  "data": [
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
      "id": "deny_all",
      "effect": "deny",
      "conditions": {},
      "restrictions": null
    }
  ]
}
```

**规则字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 唯一规则标识 |
| `effect` | string | 效果：`allow` / `deny` |
| `conditions` | object | 条件键值对（AND 逻辑） |
| `restrictions` | []string | 强制限制：`watermark` / `no_print` / `no_export` |

**支持的 conditions 键：**

| 键 | 匹配方式 | 示例 |
|----|----------|------|
| `user.id` | 精确 / `in:` 列表 | `alice`、`in:alice,bob` |
| `user.role` | 精确 / `in:` 列表 | `engineer`、`in:engineer,admin` |
| `user.project` | 精确 | `ev_project` |
| `resource.path` | 精确 / `regex:` 正则 | `regex:^projects/.*` |
| `resource.type` | 精确 | `file`、`folder` |
| `resource.sensitivity` | 精确 | `confidential`、`internal` |
| `environment.ip` | CIDR | `10.0.0.0/8` |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl http://localhost:8080/api/policy/rules \
  -H "Authorization: Bearer $TOKEN"
```

---

#### `POST /api/policy/rules`

添加一条 ABAC 规则并持久化。

**请求体：**
```json
{
  "id": "block_interns_confidential",
  "effect": "deny",
  "conditions": {
    "user.role": "intern",
    "resource.sensitivity": "confidential"
  },
  "restrictions": []
}
```

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "added"
  }
}
```

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 400 | `<error>` | 规则 ID 重复或格式错误 |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X POST http://localhost:8080/api/policy/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block_interns_confidential",
    "effect": "deny",
    "conditions": {"user.role": "intern", "resource.sensitivity": "confidential"}
  }'
```

---

#### `PUT /api/policy/rules/{id}`

更新指定 ID 的 ABAC 规则。

**路径参数：**

| 参数 | 说明 |
|------|------|
| `id` | 要更新的规则 ID |

**请求体：** 同 `POST /api/policy/rules`（完整的规则对象）。

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "updated"
  }
}
```

**错误响应：**

| 状态码 | 错误消息 | 场景 |
|:------:|----------|------|
| 404 | `<error>` | 规则 ID 不存在 |

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X PUT http://localhost:8080/api/policy/rules/block_interns_confidential \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"block_interns_confidential","effect":"deny","conditions":{"user.role":"intern"}}'
```

---

#### `DELETE /api/policy/rules/{id}`

删除指定 ID 的 ABAC 规则。

**路径参数：**

| 参数 | 说明 |
|------|------|
| `id` | 要删除的规则 ID |

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "deleted"
  }
}
```

**curl 示例：**
```bash
TOKEN="<JWT Token>"
curl -X DELETE http://localhost:8080/api/policy/rules/block_interns_confidential \
  -H "Authorization: Bearer $TOKEN"
```

---

### 2.5 Agent 端点

Agent 端点供终端代理上报文件事件和心跳。**无需 JWT**（通过全局 `AuthMiddleware` 提取 `X-User-Id` 头）。

#### `POST /api/agent/event`

上报文件监控事件（CREATE / WRITE / REMOVE / RENAME）。

**请求体：**
```json
{
  "client_id": "agent-001",
  "event": {
    "Type": "WRITE",
    "Path": "/data/monitor/projects/secret.txt",
    "OldPath": ""
  },
  "timestamp": 1719234567
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `client_id` | string | 客户端标识 |
| `event.Type` | string | 事件类型：`CREATE` / `WRITE` / `REMOVE` / `RENAME` |
| `event.Path` | string | 受影响文件的绝对路径 |
| `event.OldPath` | string | RENAME 事件的原路径（其他事件为空） |
| `timestamp` | int64 | Unix 时间戳 |

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "received"
  }
}
```

**副作用：** 事件写入 Gateway 审计日志（`Subject.Type: "agent"`）。

---

#### `POST /api/agent/heartbeat`

上报终端心跳。

**请求体：**
```json
{
  "client_id": "agent-001"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `client_id` | string | 客户端标识 |

**响应 200：**
```json
{
  "success": true,
  "data": {
    "status": "ok"
  }
}
```

**副作用：** 心跳写入 Gateway 审计日志。

---

## 3. Risk Service HTTP API

Risk Service 监听 `:8090`，提供 AI 风险评分能力，由 Gateway 内部调用。

### 3.1 健康检查

#### `GET /health`

**响应 200：**
```json
{
  "status": "ok",
  "degraded": false
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | string | 固定 `"ok"` |
| `degraded` | bool | `true` = LLM 连续失败 ≥3 次，已降级为规则评分 |

**curl 示例：**
```bash
curl http://localhost:8090/health
```

---

### 3.2 风险评分

#### `POST /api/risk/evaluate`

对一次文件访问请求执行 AI 风险评分。

**请求体（`EvaluateRequest`）：**
```json
{
  "request_id": "req-001",
  "subject": {
    "id": "alice",
    "role": "engineer",
    "project": "ev_project",
    "department": "battery_rnd"
  },
  "resource": {
    "path": "projects/battery_spec.xlsx",
    "sensitivity": "confidential",
    "type": "file"
  },
  "environment": {
    "time": "2026-06-24T21:30:00+08:00",
    "ip": "10.0.0.55",
    "device_fingerprint": "abc123",
    "user_agent": "Mozilla/5.0"
  },
  "context": {
    "recent_access_count_1h": 5,
    "unique_files_accessed_1h": 3,
    "is_work_hours": false,
    "is_known_location": true,
    "is_trusted_device": false,
    "content_summary": "电池规格参数：容量 150kWh，电压范围 400-800V"
  }
}
```

**请求字段详细说明：**

`subject` — 访问主体：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `id` | string | ✅ | 用户标识 |
| `role` | string | ✅ | 角色（`engineer` / `admin` / `intern` 等） |
| `project` | string | ✅ | 所属项目 |
| `department` | string | — | 部门（可选） |

`resource` — 访问资源：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `path` | string | ✅ | 文件路径 |
| `sensitivity` | string | ✅ | 敏感度（`confidential` / `internal` / `public`） |
| `type` | string | — | 资源类型（`file` / `folder`） |

`environment` — 环境上下文：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `time` | string | ✅ | ISO 8601 格式时间 |
| `ip` | string | ✅ | 客户端 IP 地址 |
| `device_fingerprint` | string | — | 设备指纹 |
| `user_agent` | string | — | User-Agent |

`context` — 风险上下文：

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `recent_access_count_1h` | int | ✅ | 最近 1 小时访问次数 |
| `unique_files_accessed_1h` | int | ✅ | 最近 1 小时唯一文件数 |
| `is_work_hours` | bool | ✅ | 是否工作时间（09:00-18:00） |
| `is_known_location` | bool | ✅ | IP 是否可信位置 |
| `is_trusted_device` | bool | — | 是否企业注册设备 |
| `content_summary` | string | — | 文件内容摘要（已 PII 脱敏） |

> `content_summary` 会在 Risk Service 内部再次经 `Sanitize()` 脱敏后再发送至 LLM。

**响应 200（`EvaluateResponse`）：**
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
  "reason": "非工作时间访问电池参数文件，建议启用 MFA 验证",
  "cached": false,
  "model": "deepseek-v4-pro",
  "latency_ms": 234
}
```

**响应字段说明：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `request_id` | string | 请求 ID（原样返回） |
| `risk_score` | float64 | 风险评分 **0.0–1.0** |
| `risk_level` | string | 风险等级：`low` / `medium` / `high` / `critical` |
| `factors` | object | 四个维度的子评分（0.0–1.0） |
| `factors.time_anomaly` | float64 | 时间异常度 |
| `factors.location_anomaly` | float64 | 位置异常度 |
| `factors.behavior_volume` | float64 | 行为量异常度 |
| `factors.content_sensitivity` | float64 | 内容敏感度 |
| `recommendation` | string | 建议动作：`allow` / `mfa` / `approval` / `deny` |
| `reason` | string | 简短中文解释 |
| `cached` | bool | 是否来自缓存 |
| `model` | string | 使用的 LLM 模型名称 |
| `latency_ms` | int64 | 评分耗时（毫秒） |

**评分 → 动作映射（`RiskAction()`）：**

| 评分范围 | 等级 | 动作 |
|----------|------|------|
| 0.0 ≤ score < 0.3 | `low` | `allow` |
| 0.3 ≤ score < 0.6 | `medium` | `mfa` |
| 0.6 ≤ score < 0.8 | `high` | `approval` |
| 0.8 ≤ score ≤ 1.0 | `critical` | `deny` |

> 如果 LLM 返回的 `recommendation` 字段非空且为已知值，则**优先使用** LLM 建议的动作，忽略评分阈值映射。

**缓存机制：**

Risk Service 使用 LRU 缓存（`max_entries` 条 / `ttl` 过期）。同一用户 + 同一文件 + 同一时间窗口内的请求命中缓存，`cached: true` 且不调用 LLM。

**降级机制：**

LLM 调用连续失败 3 次后，Scorer 标记 `degraded: true`，后续请求**跳过 LLM，仅使用确定性规则评分**（`[rule fallback]` 前缀）。可通过 `GET /health` 查看降级状态。

**curl 示例：**
```bash
curl -X POST http://localhost:8090/api/risk/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "test-001",
    "subject": {"id": "alice", "role": "engineer", "project": "ev_project"},
    "resource": {"path": "projects/battery_spec.xlsx", "sensitivity": "confidential"},
    "environment": {"time": "2026-06-24T21:30:00+08:00", "ip": "10.0.0.55"},
    "context": {"recent_access_count_1h": 5, "unique_files_accessed_1h": 3, "is_work_hours": false, "is_known_location": true, "content_summary": "电池参数"}
  }'
```

**LLM 服务不可用时的响应：**

Risk Service 始终返回 HTTP 200（降级为确定性规则评分）：

```json
{
  "risk_score": 0.1,
  "risk_level": "low",
  "recommendation": "allow",
  "reason": "evaluation error, defaulting to allow"
}
```

---

## 4. KMS gRPC API

| 属性 | 值 |
|------|-----|
| 端口 | `50051` |
| 服务名 | `kms.KeyManagementService` |
| Proto | `api/proto/kms.proto` |
| 健康检查 | `grpc_health_probe -addr=localhost:50051` |

### RPC 列表

#### `GenerateKey`

生成 256 位随机 AES 密钥。

**请求：**
```protobuf
message GenerateKeyRequest {
  string algorithm = 1;  // "AES256" 或 "RSA"
  int32 size = 2;        // 密钥位数（AES256 → 256）
}
```

**响应：**
```protobuf
message GenerateKeyResponse {
  string key_id = 1;       // 密钥唯一标识
  string key_material = 2; // Base64 密钥材料（对称）/ PEM（非对称）
}
```

**grpcurl 示例：**
```bash
grpcurl -plaintext -d '{"algorithm":"AES256","size":256}' \
  localhost:50051 kms.KeyManagementService/GenerateKey
```

---

#### `Encrypt`

AES-256-GCM 加密。

**请求：**
```protobuf
message EncryptRequest {
  string key_id = 1;   // GenerateKey 返回的 key_id
  bytes plaintext = 2; // 原始明文
}
```

**响应：**
```protobuf
message EncryptResponse {
  string ciphertext = 1; // Base64 密文
}
```

**grpcurl 示例：**
```bash
grpcurl -plaintext -d '{"key_id":"<KEY_ID>","plaintext":"SGVsbG8gV29ybGQ="}' \
  localhost:50051 kms.KeyManagementService/Encrypt
```

---

#### `Decrypt`

AES-256-GCM 解密。

**请求：**
```protobuf
message DecryptRequest {
  string key_id = 1;      // 加密时使用的 key_id
  string ciphertext = 2;  // Base64 密文
}
```

**响应：**
```protobuf
message DecryptResponse {
  bytes plaintext = 1; // 解密后的原始明文
}
```

---

#### `RotateKey`

轮换指定密钥，返回新密钥 ID。旧密钥保留用于解密已有密文。

**请求：**
```protobuf
message RotateKeyRequest {
  string key_id = 1; // 要轮换的密钥 ID
}
```

**响应：**
```protobuf
message RotateKeyResponse {
  string new_key_id = 1; // 新密钥 ID
}
```

**副作用：** 客户端本地缓存更新为 `new_key_id`，后续 Encrypt 使用新密钥。

---

#### `RevokeKey`

吊销指定密钥，从存储中删除。如果吊销的是当前缓存密钥，缓存被清除。

**请求：**
```protobuf
message RevokeKeyRequest {
  string key_id = 1; // 要吊销的密钥 ID
}
```

**响应：**
```protobuf
message RevokeKeyResponse {
  bool success = 1;
}
```

---

## 5. Audit gRPC API

| 属性 | 值 |
|------|-----|
| 端口 | `8082` |
| 服务名 | `audit.AuditService` |
| Proto | `api/proto/audit.proto` |
| Reflection | ✅ 已注册 |

### RPC 列表

#### `Log`

写入一条审计事件。

**请求：**
```protobuf
message LogRequest {
  AuditEvent event = 1;
}

message AuditEvent {
  string id = 1;
  google.protobuf.Timestamp timestamp = 2;
  string event_type = 3;         // access | download | upload | delete | move
  string subject_id = 4;
  string subject_role = 5;
  string resource_path = 6;
  string resource_sensitivity = 7;
  string environment_ip = 8;
  bool allowed = 9;
  string reason = 10;
  string result = 11;            // success | failure
  map<string, string> details = 12; // risk_score, dlp_action, risk_mode 等扩展字段
}
```

**响应：**
```protobuf
message LogResponse {
  bool success = 1;
  string event_id = 2;
}
```

**grpcurl 示例：**
```bash
grpcurl -plaintext -d '{
  "event": {
    "id": "evt-001",
    "event_type": "access",
    "subject_id": "alice",
    "subject_role": "engineer",
    "resource_path": "projects/battery.xlsx",
    "allowed": true,
    "result": "success"
  }
}' localhost:8082 audit.AuditService/Log
```

---

#### `Query`

按条件分页查询审计事件。

**请求：**
```protobuf
message QueryRequest {
  string subject_id = 1;
  string resource_path = 2;
  string event_type = 3;
  google.protobuf.Timestamp start_time = 4;
  google.protobuf.Timestamp end_time = 5;
  int32 limit = 6;
  int32 offset = 7;
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `subject_id` | string | 按用户 ID 筛选 |
| `resource_path` | string | 按文件路径筛选 |
| `event_type` | string | 按事件类型筛选 |
| `start_time` | Timestamp | 开始时间 |
| `end_time` | Timestamp | 结束时间 |
| `limit` | int32 | 分页大小（默认 0 = 不限） |
| `offset` | int32 | 偏移量 |

**响应：**
```protobuf
message QueryResponse {
  repeated AuditEvent events = 1;
  int32 total = 2;
}
```

---

#### `StreamLog`

流式接收审计事件（高性能批量场景）。

**请求：** stream `LogRequest`

**响应：**
```protobuf
message StreamLogResponse {
  int32 received = 1; // 已接收事件数
}
```

---

## 6. Policy gRPC API

| 属性 | 值 |
|------|-----|
| 端口 | `8081` |
| 服务名 | `policy.PolicyService` |
| Proto | `api/proto/policy.proto` |
| Reflection | ✅ 已注册 |

### 数据结构

```protobuf
message Subject {
  string id = 1;
  string type = 2;               // user | device | service
  string role = 3;
  string project = 4;
  map<string, string> attributes = 5;
}

message Resource {
  string id = 1;
  string type = 2;               // file | folder
  string path = 3;
  string sensitivity = 4;
  repeated string tags = 5;
  map<string, string> attributes = 6;
}

message Environment {
  string time = 1;
  string ip = 2;
  string device_id = 3;
  string os = 4;
  map<string, string> attributes = 5;
}

message Rule {
  string id = 1;
  string effect = 2;             // allow | deny
  map<string, string> conditions = 3;
  repeated string restrictions = 4; // watermark | no_print | no_export
}

message Decision {
  bool allowed = 1;
  string reason = 2;
  repeated string restrictions = 3;
}
```

### RPC 列表

#### `Evaluate`

评估 ABAC 策略。

**请求：**
```protobuf
message EvaluateRequest {
  Subject subject = 1;
  Resource resource = 2;
  Environment environment = 3;
}
```

**响应：**
```protobuf
message EvaluateResponse {
  Decision decision = 1;
}
```

**grpcurl 示例：**
```bash
grpcurl -plaintext -d '{
  "subject": {"id":"alice","role":"engineer","type":"user"},
  "resource": {"path":"projects/battery.xlsx","type":"file","sensitivity":"confidential"},
  "environment": {"time":"2026-06-24T21:30:00+08:00","ip":"10.0.0.55"}
}' localhost:8081 policy.PolicyService/Evaluate
```

---

#### `GetRules`

获取所有规则。

**请求：**
```protobuf
message GetRulesRequest {}
```

**响应：**
```protobuf
message GetRulesResponse {
  repeated Rule rules = 1;
}
```

---

#### `AddRule`

添加规则（自动持久化到 `rules_file`）。

**请求：**
```protobuf
message AddRuleRequest {
  Rule rule = 1;
}
```

**响应：**
```protobuf
message AddRuleResponse {
  bool success = 1;
  string rule_id = 2;
}
```

---

#### `UpdateRule`

更新指定规则。

**请求：**
```protobuf
message UpdateRuleRequest {
  string rule_id = 1;
  Rule rule = 2;
}
```

**响应：**
```protobuf
message UpdateRuleResponse {
  bool success = 1;
}
```

---

#### `DeleteRule`

删除指定规则。

**请求：**
```protobuf
message DeleteRuleRequest {
  string rule_id = 1;
}
```

**响应：**
```protobuf
message DeleteRuleResponse {
  bool success = 1;
}
```

---

#### `Watch`

监听规则变更（服务端流式推送）。

**请求：**
```protobuf
message WatchRequest {}
```

**响应（流式）：**
```protobuf
message RuleUpdate {
  enum Action {
    ADDED = 0;
    UPDATED = 1;
    DELETED = 2;
  }
  Action action = 1;
  Rule rule = 2;
}
```

---

## 7. 错误码速查

### HTTP 状态码

| 状态码 | 含义 | 常见场景 |
|:------:|------|----------|
| 200 | 成功 | 正常响应 |
| 400 | 请求错误 | JSON 格式错误、缺少必填字段、规则 ID 冲突 |
| 401 | 未认证 | JWT 缺失/无效/过期、密码错误 |
| 403 | 禁止 | ABAC 拒绝、AI 评分拒绝、DLP 拦截、Risk 降级 deny |
| 404 | 未找到 | 文件不存在、规则不存在、用户不存在 |
| 500 | 服务端错误 | KMS/存储异常、加密/解密失败 |

### gRPC 状态码

| 状态码 | 场景 |
|:------:|------|
| `InvalidArgument` | 缺少必填字段（`event is required`）、规则格式错误 |
| `NotFound` | 更新的规则 ID 不存在 |
| `Internal` | 日志写入失败、策略评估异常 |
| `Unavailable` | 服务未启动或网络不通 |

### 通用错误响应体

```json
{
  "success": false,
  "error": "具体错误描述"
}
```
