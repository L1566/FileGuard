# FileGuard 安全测试清单

> 本文档列出在生产部署前应完成的安全审查项。

## 身份认证与授权

- [x] JWT 令牌签名验证（HS256）
- [x] TOTP 双因素认证
- [x] ABAC 属性级访问控制
- [x] 密码 bcrypt 哈希存储
- [ ] OAuth2 / LDAP 企业身份源集成
- [ ] 令牌刷新与吊销机制
- [ ] 会话超时与并发限制

## 数据保护

- [x] AES-256-GCM 文件加密
- [x] 密钥与数据分离存储（KMS）
- [x] 密钥文件持久化（0600 权限）
- [x] DLP 敏感内容识别与阻断
- [ ] 传输层 TLS 加密（当前仅 HTTP/gRPC 明文）
- [ ] 数据库/缓存加密
- [ ] 密钥自动轮换策略

## 审计与合规

- [x] 全量文件操作审计日志
- [x] JSON 行格式日志（兼容 ELK/Splunk）
- [ ] 日志哈希上链防篡改
- [ ] 审计日志签名验证
- [ ] 合规报告生成（等保 2.0 / GDPR）

## 网络安全

- [x] 零信任架构（所有请求经网关评估）
- [ ] mTLS 服务间通信
- [ ] API 速率限制
- [ ] WAF / DDoS 防护集成
- [ ] 网络策略隔离（K8s NetworkPolicy）

## 应用安全

- [x] 静态代码分析（golangci-lint）
- [x] 竞态条件检测（-race）
- [ ] 模糊测试（fuzzing）
- [ ] 依赖漏洞扫描（govulncheck / Snyk）
- [ ] 容器镜像漏洞扫描
- [ ] 安全 HTTP 头（CSP, HSTS, X-Frame-Options）

## 运维安全

- [x] 容器化部署（Dockerfile）
- [x] 非 root 用户运行
- [x] 最小镜像（alpine + 多阶段构建）
- [x] 优雅关闭（SIGTERM）
- [ ] 密钥管理：K8s Secrets 替代 ConfigMap 中的敏感值
- [ ] 只读根文件系统
- [ ] Pod Security Policy / SecurityContext
- [ ] 日志采集与集中监控

---

**状态说明：** [x] 已完成  [ ] 待实现
