# FileGuard AI 升级 — 动态风险评分服务设计规格

> 状态：已批准 | 日期：2026-06-23 | 方案：B（智能中间件）

## 1. 目标

将 FileGuard 从纯规则驱动的静态访问控制升级为 **AI 增强的动态风险决策系统**。在不破坏现有架构的前提下，新增独立的 Risk Service 微服务，利用云端 LLM 对每次文件访问请求进行实时多维风险评分。

## 2. 确认的设计决策

| 决策点 | 选择 |
|--------|------|
| 核心方向 | 动态风险决策（实时评分替代静态 ABAC 规则） |
| AI 部署模式 | 云端 API 起步（零运维，模型最新） |
| 数据隐私边界 | 脱敏后全量内容（PII 本地脱敏后发送） |
| 架构策略 | 方案 B：独立 Risk Service 微服务嵌入现有网关 |

## 3. 架构概览

```
Client → Gateway (现有) → Risk Service (新增) → Cloud LLM API
              │                    │
              ├─ ABAC 快路径        ├─ PII 脱敏
              ├─ DLP 检测           ├─ Prompt 构造
              └─ 审计日志           ├─ 缓存层
                                   └─ 降级逻辑
```

**数据流：**
1. Gateway 拦截文件请求 → 提取 Subject/Resource/Environment
2. ABAC 快速初筛（黑名单直接拒绝）
3. 异步调用 Risk Service 获取风险评分
4. Risk Service：脱敏 → 构造 prompt → 调用 Claude API → 解析 JSON 响应
5. Gateway 根据评分 + 建议动作决策：allow / mfa / approval / deny
6. 完整决策链记录到审计日志

**延迟预算：** 约 210ms（其中 ~200ms 为 LLM API，缓存命中时 ~7ms）

## 4. 渐进上线策略

| 阶段 | 模式 | 行为 | 风险 |
|------|------|------|------|
| Phase 1 | Shadow | Risk Service 评分并记录，Gateway 仍用 ABAC 决策 | 零 |
| Phase 2 | Monitor | 低风险场景使用 AI 评分，高风险保留 ABAC | 低 |
| Phase 3 | Active | 全量切换为 AI + ABAC 混合决策 | 可控 |

配置项 `risk.mode` 控制：`shadow` → `monitor` → `active`

## 5. API 契约

### POST /api/risk/evaluate

**Request:**
```json
{
  "request_id": "req_abc123",
  "subject": {
    "id": "alice",
    "role": "battery_engineer",
    "project": "ev_battery",
    "department": "R&D"
  },
  "resource": {
    "path": "/secure/battery/BOM_v3.xlsx",
    "sensitivity": "confidential",
    "type": "spreadsheet"
  },
  "environment": {
    "time": "2026-06-23T22:15:00+08:00",
    "ip": "203.0.113.42",
    "device_fingerprint": "dvc_xyz789"
  },
  "context": {
    "recent_access_count_1h": 47,
    "unique_files_accessed_1h": 32,
    "is_work_hours": false,
    "is_known_location": false,
    "content_summary": "BOM, 电池模组规格, 电芯参数..."
  }
}
```

**Response:**
```json
{
  "request_id": "req_abc123",
  "risk_score": 0.72,
  "risk_level": "high",
  "factors": {
    "time_anomaly": 0.35,
    "location_anomaly": 0.22,
    "behavior_volume": 0.12,
    "content_sensitivity": 0.03
  },
  "recommendation": "approval",
  "reason": "非工作时间 + 非受信IP + 异常高频访问。建议主管审批。",
  "cached": false,
  "model": "claude-sonnet-4-6",
  "latency_ms": 187
}
```

## 6. 风险评分 → 动作映射

| 评分范围 | 风险等级 | 推荐动作 | Gateway 行为 |
|----------|----------|----------|-------------|
| 0.0–0.3 | low | allow | 直接放行 |
| 0.3–0.6 | medium | mfa | 触发 Step-up MFA |
| 0.6–0.8 | high | approval | 返回 202，需主管审批 |
| 0.8–1.0 | critical | deny | 返回 403，触发告警 |

## 7. PII 脱敏规则

在本地完成脱敏后再发送到云端 AI，确保敏感数据不出境：

| 类别 | 原始示例 | 脱敏后 | 方法 |
|------|----------|--------|------|
| 身份证号 | 110101199001011234 | `110101****1234` | 正则替换 |
| 手机号 | 13812345678 | `138****5678` | 正则替换 |
| 邮箱 | alice@evcompany.com | `a***@evcompany.com` | 正则替换 |
| IP 地址 | 192.168.1.100 | `192.168.*.*` | 子网掩码 |
| 银行卡号 | 6222021234567890 | `****7890` | Luhn 校验 + 替换 |
| 中文人名 | 张三 | `张*` | 正则替换 |
| 金额 | ¥1,234,567.89 | `¥***` | 正则替换 |
| 车牌号 | 京A12345 | `京A***` | 正则替换 |

实现：纯 Go 正则 + 规则引擎，零外部依赖，延迟 <1ms。

## 8. 容错与降级

| 场景 | 处理 |
|------|------|
| JSON 解析失败 | 返回默认低风险（不阻断业务） |
| risk_score 超出 0~1 | 钳位到范围 |
| API 超时（>500ms） | 返回缓存值或默认值 |
| API 连续失败 3 次 | 告警 + 临时降级到纯 ABAC |
| Risk Service 不可达 | Gateway 退化为纯 ABAC（优雅降级） |

## 9. 缓存策略

- **缓存键：** `hash(subject_role + resource_path_pattern + env_ip_prefix + time_window_5min)`
- **TTL：** 5 分钟
- **实现：** LRU 内存缓存（hashicorp/golang-lru 或自实现）
- **命中率预期：** 日常操作 >70%

## 10. 新增配置

```yaml
# configs/gateway.yaml 新增
risk:
  enabled: true
  mode: shadow          # shadow | monitor | active
  service_url: localhost:8090
  cache_ttl: 5m
  timeout: 500ms
  fallback: allow       # allow | deny | abac_only
```

```yaml
# configs/riskservice.yaml 新增
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

## 11. 代码组织

### 新增文件（8 个）

| 文件 | 行数 | 说明 |
|------|------|------|
| `cmd/riskservice/main.go` | ~80 | Risk Service 入口 + 路由 + 优雅关闭 |
| `internal/riskservice/handler/evaluate.go` | ~150 | `/api/risk/evaluate` 处理逻辑 |
| `pkg/risk/types.go` | ~80 | 请求/响应数据结构 |
| `pkg/risk/client.go` | ~80 | Gateway 侧 HTTP 调用客户端 |
| `pkg/risk/scorer.go` | ~200 | 评分逻辑 + LRU 缓存 + 降级 |
| `pkg/risk/sanitizer.go` | ~150 | PII 脱敏引擎 |
| `pkg/risk/sanitizer_test.go` | ~100 | 脱敏规则测试 |
| `pkg/risk/prompt.go` | ~120 | Prompt 模板管理 |
| `configs/riskservice.yaml` | ~20 | Risk Service 配置 |

### 修改文件（4 个）

| 文件 | 改动 | 说明 |
|------|------|------|
| `pkg/config/config.go` | +40 行 | 新增 `RiskSettings`、`RiskServiceConfig` |
| `configs/gateway.yaml` | +6 行 | 新增 `risk` 配置节点 |
| `internal/gateway/handler/file.go` | +50 行 | 注入 `riskClient`，新增 `evaluateRisk()` |
| `cmd/gateway/main.go` | +20 行 | 初始化 `riskClient` |

**总计：约 1070 行新代码 + 100 行测试 = ~1170 行**

### 依赖关系

```
cmd/riskservice → internal/riskservice/handler → pkg/risk/{scorer, sanitizer, prompt}
cmd/gateway → pkg/risk/client (HTTP) → Risk Service
```

- `pkg/risk/client`：轻量 HTTP client，仅依赖标准库
- `pkg/risk/scorer`：调用外部 LLM API，带缓存和降级
- `pkg/risk/sanitizer`：纯 Go 正则引擎，零外部依赖

## 12. 新增外部依赖

| 依赖 | 用途 |
|------|------|
| `github.com/hashicorp/golang-lru` | LRU 缓存（scorer 评分结果） |

可选（如使用 Anthropic SDK 而非原始 HTTP）：
| `github.com/anthropics/anthropic-sdk-go` | Claude API 类型安全调用 |

## 13. 安全考量

- LLM API Key 通过环境变量注入（`FILEGUARD_LLM_API_KEY`），不写入配置文件
- 脱敏在 Risk Service 本地完成后再发云端，敏感数据不出网
- 审计日志记录完整决策链（含 risk_score + reason），支持事后审查
- Risk Service 与 Gateway 之间建议使用 mTLS（生产环境）

## 14. 测试计划

| 测试类型 | 内容 | 覆盖文件 |
|----------|------|----------|
| 单元测试 | 脱敏规则每种 PII 类型 | `sanitizer_test.go` |
| 单元测试 | Prompt 模板渲染正确性 | `prompt_test.go` |
| 单元测试 | 缓存命中/过期/淘汰 | `scorer_test.go` |
| 集成测试 | Gateway → Risk Service → LLM 端到端 | `test/integration/risk_test.go` |
| 集成测试 | Risk Service 不可达时降级行为 | `test/integration/risk_test.go` |
