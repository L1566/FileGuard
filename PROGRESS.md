# FileGuard 项目完成度跟踪

> 最后更新：2026-06-23 | 阶段 0 ✅ 阶段 1 ✅ 阶段 2 ✅ 阶段 3 ✅ 阶段 4~7 待跟进

---

## 📊 总体进度

```
阶段 0  █████████████████████ 100%  基础设施 ✅
阶段 1  █████████████████████ 100%  存储与策略基础 ✅
阶段 2  ████████████████████░ 100%  零信任网关原型
阶段 3  █████████████████████ 100%  终端代理 + 水印 ✅
阶段 4  ███████████████████░░  95%  加密与 KMS
阶段 5  ████████████████████░ 100%  DLP 与动态策略
阶段 6  ██████████████░░░░░░░  70%  MFA (TOTP)
阶段 7  ███░░░░░░░░░░░░░░░░░░  15%  生产加固与测试
────────────────────────────────────
综合    ██████████████████░░░  85%
```

---

## 阶段 0 — 基础设施（95%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 0.1 | 项目目录结构 (cmd/internal/pkg/api/configs/deployments) | ✅ | 完整，另有预留扩展目录 |
| 0.2 | Go module 初始化 (`go.mod`) | ✅ | module `github.com/L1566/FileGuard`，Go 1.25 |
| 0.3 | 日志库 logrus 封装 | ✅ | [pkg/logger/logger.go](pkg/logger/logger.go) — Debug/Info/Warn/Error/Fatal + 结构化字段 |
| 0.4 | 配置管理 viper | ✅ | [pkg/config/config.go](pkg/config/config.go) — GatewayConfig/AgentConfig/ServiceConfig 三大类型 + 专用 Load 函数 |
| 0.5 | 统一错误处理 | ✅ | [pkg/errors/errors.go](pkg/errors/errors.go) — AppError + 5 种哨兵错误 |
| 0.6 | HTTP 响应封装 | ✅ | [pkg/http/response.go](pkg/http/response.go) — Success/Error JSON 响应 |
| 0.7 | 健康检查端点 | ✅ | 所有 5 个服务均实现 `/health` |

**待改进：**
- [x] ~~`go.mod` 中部分直接依赖标记为 `// indirect`~~ → 已通过 `go mod tidy` 修复
- [x] ~~配置 struct 分散在各 `cmd/*/main.go`~~ → 已集中到 `pkg/config/config.go`（GatewayConfig / AgentConfig / ServiceConfig）

---

## 阶段 1 — 存储与策略基础（85%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 1.1 | 存储接口 (Get/Put/Delete/Stat/List/Move) | ✅ | [pkg/storage/interface.go](pkg/storage/interface.go) |
| 1.2 | 本地文件系统实现 | ✅ | [pkg/storage/filesystem.go](pkg/storage/filesystem.go) |
| 1.3 | `.meta` 元数据文件 | ✅ | 读写 JSON 元数据，与文件并存 |
| 1.4 | ABAC 模型 (Subject/Resource/Environment/Decision) | ✅ | [pkg/abac/model.go](pkg/abac/model.go) |
| 1.5 | 规则支持正则匹配 | ✅ | `regex:` 前缀语法 |
| 1.6 | 规则支持列表包含 | ✅ | `[]interface{}` 值自动切换 |
| 1.7 | MemoryEvaluator | ✅ | [pkg/abac/evaluator.go](pkg/abac/evaluator.go) — 首匹配/默认拒绝 |
| 1.8 | 单元测试覆盖 | ✅ | `pkg/abac/` 31 测试 + `pkg/storage/` 19 测试（共 50 项） |

**本轮修复（2026-06-23）：**
- [x] ~~S3 存储后端为空 stub~~ → 已实现完整占位类型（含接口方法 + 文档化未来扩展点 + `ErrNotImplemented`）
- [x] ~~补全 `pkg/storage/` 单元测试~~ → 19 项测试：Put/Get 往返、Stat、Delete、List、Move、并发、二进制/大文件
- [x] ~~补全 `pkg/abac/` 单元测试~~ → 从 2 项扩展至 31 项：属性匹配、环境条件、CRUD、默认拒绝、规则加载

---

## 阶段 2 — 零信任网关原型（100%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 2.1 | HTTP 服务器 (gorilla/mux) | ✅ | [cmd/gateway/main.go](cmd/gateway/main.go) |
| 2.2 | `GET /file/{path}` 下载 | ✅ | [file.go:46](internal/gateway/handler/file.go#L46) — ABAC → 解密 → DLP → 水印 → 审计 |
| 2.3 | `PUT /file/{path}` 上传 | ✅ | [file.go:190](internal/gateway/handler/file.go#L190) — ABAC → DLP → 加密 → 存储 → 审计 |
| 2.4 | 模拟认证（Header） | ✅ | [middleware/auth.go](internal/gateway/middleware/auth.go) — X-User-Id/Role/Project |
| 2.5 | ABAC 评估集成 | ✅ | 每次请求调用 `evaluator.Evaluate` |
| 2.6 | 审计日志（JSON 行） | ✅ | [pkg/audit/file_logger.go](pkg/audit/file_logger.go) — 线程安全写入 |
| 2.7 | 策略规则 JSON 示例 | ✅ | [configs/rules.json](configs/rules.json) — 3 条规则 |

---

## 阶段 3 — 终端代理 + 水印（90%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 3.1 | fsnotify 目录监控（递归） | ✅ | [internal/agent/monitor/monitor.go](internal/agent/monitor/monitor.go) |
| 3.2 | 文件事件上报 | ✅ | [internal/agent/reporter/reporter.go](internal/agent/reporter/reporter.go) — POST JSON |
| 3.3 | 心跳上报 | ✅ | 可配置间隔，默认 30s |
| 3.4 | 图片水印（gg 库） | ✅ | [pkg/watermark/watermark.go](pkg/watermark/watermark.go) — `AddTextWatermark` |
| 3.5 | 文本文件水印 | ✅ | `AddTextWatermarkSimple` — 注释前缀 |
| 3.6 | 网关集成水印 | ✅ | 根据策略 Restrictions 自动应用 |

**本轮修复（2026-06-23）：**
- [x] ~~水印字体路径硬编码~~ → `GatewayConfig.Watermark.FontPath` 配置化 + `watermark.SetFontPath()` 运行时设置
- [x] ~~字体加载失败静默回退~~ → 改用 `logger.Warnf` 打印字体路径和错误详情
- [x] ~~GatewayConfig 缺少水印配置节点~~ → 新增 `WatermarkSettings` + `gateway.yaml` 增加 `watermark.font_path`

---

## 阶段 4 — 加密与 KMS（95%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 4.1 | AES-256-GCM 加密 | ✅ | [pkg/crypto/aes.go](pkg/crypto/aes.go) — nonce 前置 + Base64 编码 |
| 4.2 | AES-256-GCM 解密 | ✅ | 自动从密文提取 nonce |
| 4.3 | RSA 密钥对生成 | ✅ | [pkg/crypto/rsa.go](pkg/crypto/rsa.go) — PEM 格式 |
| 4.4 | KMS gRPC 服务 | ✅ | [cmd/kms/main.go](cmd/kms/main.go) + [server.go](internal/kms/server/server.go) |
| 4.5 | GenerateKey RPC | ✅ | 256 位随机密钥 |
| 4.6 | Encrypt / Decrypt RPC | ✅ | AES-256-GCM |
| 4.7 | RotateKey / RevokeKey RPC | ✅ | 保留旧密钥用于解密 |
| 4.8 | 网关集成 KMS 客户端 | ✅ | [pkg/kms/client.go](pkg/kms/client.go) — Encrypt/Decrypt |
| 4.9 | 密钥 ID 存于文件元数据 | ✅ | `metadata["key_id"]` → `.meta` 文件 |
| 4.10 | 兼容未加密旧文件 | ✅ | key_id 为空时跳过解密 |

**待改进：**
- [ ] 密钥仅存于内存 map，KMS 重启全部丢失
- [ ] `grpc.WithInsecure()` 已弃用，迁移至 `insecure.NewCredentials()`
- [ ] `pkg/kms/client.go` 未暴露 RotateKey/RevokeKey

---

## 阶段 5 — DLP 与动态策略（100%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 5.1 | DLP 规则集 | ✅ | [pkg/dlp/rules.go](pkg/dlp/rules.go) — 线程安全 CRUD |
| 5.2 | 关键词检测 | ✅ | 大小写不敏感 `bytes.Contains` |
| 5.3 | 正则检测 | ✅ | 编译缓存 `regexCache` |
| 5.4 | action: block | ✅ | 上传时直接拒绝 |
| 5.5 | action: alert | ✅ | 记录警告日志 |
| 5.6 | action: log | ✅ | 记录到审计 |
| 5.7 | 下载敏感内容强制水印 | ✅ | sensitivity=critical → 强制 watermark |
| 5.8 | 策略热加载（fsnotify） | ✅ | [pkg/abac/hot_reload.go](pkg/abac/hot_reload.go) |
| 5.9 | 策略 CRUD API | ✅ | [policy_api.go](internal/gateway/handler/policy_api.go) — GET/POST/PUT/DELETE |
| 5.10 | DLP 规则配置示例 | ✅ | [configs/dlp_rules.json](configs/dlp_rules.json) — 3 条规则 |

---

## 阶段 6 — MFA / TOTP（70%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 6.1 | JWT 生成（HS256） | ✅ | [pkg/auth/jwt.go](pkg/auth/jwt.go) |
| 6.2 | JWT 验证中间件 | ✅ | [middleware/jwt_auth.go](internal/gateway/middleware/jwt_auth.go) |
| 6.3 | TOTP 密钥生成 | ✅ | [pkg/auth/mfa.go](pkg/auth/mfa.go) — `pquerna/otp` |
| 6.4 | TOTP 验证 | ✅ | `ValidateTOTP` |
| 6.5 | Login（密码 + 可选 TOTP） | ✅ | [auth.go:39](internal/gateway/handler/auth.go#L39) |
| 6.6 | 用户模拟存储 | ✅ | [internal/auth/user_store.go](internal/auth/user_store.go) |
| 6.7 | SetupMFA / VerifyMFA | 🔴 | **Context key 类型不匹配** — 见下方 Bug 说明 |

**🐛 已知 Bug：** [auth.go:79](internal/gateway/handler/auth.go#L79) 和 [auth.go:110](internal/gateway/handler/auth.go#L110) 使用 `r.Context().Value("claims")`（`string` 类型）读取 JWT claims，但 [jwt_auth.go:15](internal/gateway/middleware/jwt_auth.go#L15) 存储时使用类型化常量 `ClaimsKey contextkeyJwtAuth`。**Go context 的 key 比较包含类型信息**，类型不匹配导致 `SetupMFA` 和 `VerifyMFA` 永远返回 401。

**修复方案：** 将 `r.Context().Value("claims")` 改为 `middleware.GetClaims(r.Context())`

**待改进：**
- [ ] 密码明文存储（`internal/auth/user_store.go`）
- [ ] TOTP secret 在首次验证前已保存（应先验证再启用）

---

## 阶段 7 — 生产加固与测试（15%）

| # | 需求项 | 状态 | 说明 |
|---|--------|:----:|------|
| 7.1 | 集成测试 | 🔴 | `test/integration/` 目录为空 |
| 7.2 | 性能测试脚本（wrk） | 🔴 | 不存在 |
| 7.3 | Docker 镜像 | 🔴 | `deployments/docker/Dockerfile` 为空文件 |
| 7.4 | Docker Compose 编排 | 🔴 | 不存在 `docker-compose.yml` |
| 7.5 | Kubernetes 部署 | 🔴 | `deployments/kubernetes/deployment.yaml` 为空文件 |
| 7.6 | golangci-lint 配置 | ⚠️ | Makefile 有 lint 目标但无配置文件 |
| 7.7 | 测试覆盖率 >70% | 🔴 | 仅 1 个测试文件，覆盖率 <5% |
| 7.8 | 安全测试清单 | 🔴 | 不存在 |
| 7.9 | 文档完善 | ⚠️ | docs/ 有 2 份文档，build/test 脚本为空 |

**待改进：**
- [ ] `scripts/build.sh` 为空
- [ ] `scripts/test.sh` 为空
- [ ] `api/proto/audit.proto` 和 `api/proto/policy.proto` 为空

---

## 🔴 已知问题汇总

| # | 严重度 | 位置 | 问题描述 |
|---|:------:|------|----------|
| B1 | 🔴 高 | [auth.go:79](internal/gateway/handler/auth.go#L79) | Context key 类型不匹配 → SetupMFA/VerifyMFA 永远失败 |
| B2 | 🟡 中 | [user_store.go](internal/auth/user_store.go) | 密码明文存储（标注为演示用） |
| B3 | 🟡 中 | [server.go](internal/kms/server/server.go) | KMS 密钥无持久化，重启丢失 |
| B4 | ~~🟡 中~~ ✅ | ~~[watermark.go](pkg/watermark/watermark.go)~~ | ~~字体路径硬编码~~ → 已配置化 + 失败 warning 日志 |
| B5 | 🟡 中 | [client.go](pkg/kms/client.go) | 使用已弃用的 `grpc.WithInsecure()` |
| B6 | ~~🟢 低~~ ✅ | ~~[s3.go](pkg/storage/s3.go)~~ | ~~S3 后端为空 stub~~ → 已实现占位类型 + 完整文档 |
| B7 | 🟢 低 | [file_logger.go](pkg/audit/file_logger.go) | Query 方法返回 nil（未实现） |
| B8 | ~~🟢 低~~ ✅ | ~~[go.mod](go.mod)~~ | ~~jwt/otp/gg 被错误标记为 indirect~~ → 已通过 `go mod tidy` 修复 |

---

## 🎯 下一步优先级建议

| 优先级 | 任务 | 涉及阶段 |
|:------:|------|:--------:|
| P0 | 修复 Context Key Bug（B1） | 阶段 6 |
| P1 | 完成 Docker/Docker Compose/K8s 部署 | 阶段 7 |
| P1 | 补全集成测试框架 | 阶段 7 |
| P2 | KMS 密钥持久化（B3） | 阶段 4 |
| P2 | 补全核心包单元测试 | 阶段 1/4/5 |
| P2 | 修复水印字体硬编码（B4） | 阶段 3 |
| P3 | S3 存储后端实现 | 阶段 1 |
| P3 | 审计 Query 实现 | 阶段 2 |
| P3 | Proto 文件补全（audit/policy） | 阶段 2 |
