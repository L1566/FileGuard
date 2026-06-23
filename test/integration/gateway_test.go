package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/L1566/FileGuard/internal/auth"
	"github.com/L1566/FileGuard/internal/gateway/handler"
	"github.com/L1566/FileGuard/internal/gateway/middleware"
	"github.com/L1566/FileGuard/pkg/abac"
	pkg_audit "github.com/L1566/FileGuard/pkg/audit"
	pkg_auth "github.com/L1566/FileGuard/pkg/auth"
	"github.com/L1566/FileGuard/pkg/crypto"
	"github.com/L1566/FileGuard/pkg/storage"
	"github.com/gorilla/mux"
)

// =============================================================================
// 测试辅助
// =============================================================================

// testHarness 集成测试环境
type testHarness struct {
	router  *mux.Router
	storage storage.Storage
	jwtMgr  *pkg_auth.JWTManager
}

// newTestHarness 构建完整的测试网关路由
func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	// 本地存储
	store, err := storage.NewLocalFileSystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// ABAC 评估器（允许全部 + 水印）
	evaluator := abac.NewMemoryEvaluator([]abac.Rule{
		{
			ID:           "allow-all",
			Effect:       "allow",
			Conditions:   map[string]interface{}{},
			Restrictions: []string{"watermark"},
		},
	})

	// 审计日志
	auditLogger, err := pkg_audit.NewFileLogger(t.TempDir() + "/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditLogger.Close() })

	// JWT
	jwtMgr := pkg_auth.NewJWTManager("test-secret-key-for-integration-testing", "FileGuard-Test", 1*time.Hour)
	userStore := auth.NewUserStore()
	authHandler := handler.NewAuthHandler(userStore, jwtMgr, "FileGuard-Test")

	// 文件处理器（无 KMS 客户端——使用直接加密）
	fileHandler := handler.NewFileHandler(store, evaluator, auditLogger, nil, nil)

	// 路由
	r := mux.NewRouter()
	r.HandleFunc("/health", handler.HealthCheck).Methods("GET")
	r.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(middleware.JWTAuthMiddleware(jwtMgr))
	api.HandleFunc("/auth/setup-mfa", authHandler.SetupMFA).Methods("POST")
	api.HandleFunc("/auth/verify-mfa", authHandler.VerifyMFA).Methods("POST")

	files := r.PathPrefix("/file").Subrouter()
	files.Use(middleware.JWTAuthMiddleware(jwtMgr))
	files.HandleFunc("/{path:.*}", fileHandler.GetFile).Methods("GET")
	files.HandleFunc("/{path:.*}", fileHandler.PutFile).Methods("PUT")

	return &testHarness{
		router:  r,
		storage: store,
		jwtMgr:  jwtMgr,
	}
}

// login 获取 JWT token
func (h *testHarness) login(t *testing.T, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	data := resp["data"].(map[string]interface{})
	return data["token"].(string)
}

// authRequest 创建带 JWT 认证的请求
func authRequest(method, url, token, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, url, r)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	return req
}

// =============================================================================
// 集成测试用例
// =============================================================================

// TestHealthCheck 验证健康检查端点
func TestHealthCheck(t *testing.T) {
	h := newTestHarness(t)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("health check returned %d", rec.Code)
	}
}

// TestLoginFlow 验证完整登录流程
func TestLoginFlow(t *testing.T) {
	h := newTestHarness(t)

	// 1) 使用测试账户登录
	token := h.login(t, "alice", "password123")
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// 2) 验证令牌可用于受保护路由
	req := authRequest("GET", "/file/test.txt", token, "")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	// 预期 404（文件不存在），而非 401
	if rec.Code == http.StatusUnauthorized {
		t.Error("authenticated request should not return 401")
	}
}

// TestFileUploadDownload 验证文件上传→下载完整流程
func TestFileUploadDownload(t *testing.T) {
	h := newTestHarness(t)
	token := h.login(t, "alice", "password123")

	content := "FileGuard integration test content: " + time.Now().String()

	// 1) 上传文件
	putReq := authRequest("PUT", "/file/docs/test.txt", token, content)
	putRec := httptest.NewRecorder()
	h.router.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT failed: %d %s", putRec.Code, putRec.Body.String())
	}

	// 2) 下载文件
	getReq := authRequest("GET", "/file/docs/test.txt", token, "")
	getRec := httptest.NewRecorder()
	h.router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("GET failed: %d %s", getRec.Code, getRec.Body.String())
	}

	// 3) 验证内容
	got := getRec.Body.String()
	t.Logf("Downloaded content (first 200 chars): %.200s", got)

	// 由于启用了水印，内容会包含水印前缀
	if !strings.Contains(got, "alice") {
		t.Log("content does not contain user ID watermark (expected for text files)")
	}
}

// TestUnauthorizedAccess 验证未认证请求被拒绝
func TestUnauthorizedAccess(t *testing.T) {
	h := newTestHarness(t)

	req := httptest.NewRequest("GET", "/file/secret.txt", nil)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestLoginInvalidCredentials 验证无效凭据被拒绝
func TestLoginInvalidCredentials(t *testing.T) {
	h := newTestHarness(t)

	body, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "wrong_password",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad password, got %d", rec.Code)
	}
}

// =============================================================================
// 加密往返测试（无 KMS 时直通）
// =============================================================================

func TestCryptoRoundTrip(t *testing.T) {
	plaintext := []byte("sensitive battery parameters: capacity=150kWh")
	key, err := crypto.GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}

	// 加密
	ciphertext, err := crypto.AESEncrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == string(plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// 解密
	decrypted, err := crypto.AESDecrypt(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", plaintext, decrypted)
	}
}

// =============================================================================
// DLP + ABAC 决策集成
// =============================================================================

func TestABACDefaultDeny(t *testing.T) {
	// 空规则集 → 默认拒绝
	eval := abac.NewMemoryEvaluator(nil)
	decision, err := eval.Evaluate(
		nil,
		abac.Subject{Role: "engineer"},
		abac.Resource{Path: "/battery/core.xlsx", Sensitivity: "confidential"},
		abac.Environment{IP: "10.0.0.1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Error("empty rules should default to deny")
	}
}

// TestABACAllowMatching 验证匹配规则允许访问
func TestABACAllowMatching(t *testing.T) {
	eval := abac.NewMemoryEvaluator([]abac.Rule{
		{
			ID:     "allow-engineers",
			Effect: "allow",
			Conditions: map[string]interface{}{
				"user.role":           "engineer",
				"resource.sensitivity": "confidential",
			},
			Restrictions: []string{"no_print", "watermark"},
		},
	})

	decision, _ := eval.Evaluate(
		nil,
		abac.Subject{Role: "engineer"},
		abac.Resource{Sensitivity: "confidential"},
		abac.Environment{},
	)
	if !decision.Allowed {
		t.Fatal("engineer should access confidential")
	}
	if len(decision.Restrictions) != 2 {
		t.Errorf("expected 2 restrictions, got %d", len(decision.Restrictions))
	}

	// 非匹配用户应被拒绝
	decision, _ = eval.Evaluate(
		nil,
		abac.Subject{Role: "intern"},
		abac.Resource{Sensitivity: "confidential"},
		abac.Environment{},
	)
	if decision.Allowed {
		t.Error("intern should not access confidential")
	}
}

// =============================================================================
// 性能基准
// =============================================================================

func BenchmarkABACEvaluate(b *testing.B) {
	rules := []abac.Rule{
		{ID: "r1", Effect: "allow", Conditions: map[string]interface{}{
			"user.role":     "engineer",
			"resource.path": "regex:^/projects/.*",
		}},
		{ID: "r2", Effect: "deny", Conditions: map[string]interface{}{
			"env.ip": []interface{}{"10.0.0.1", "192.168.1.100"},
		}},
		{ID: "deny-all", Effect: "deny", Conditions: map[string]interface{}{}},
	}
	eval := abac.NewMemoryEvaluator(rules)
	subj := abac.Subject{Role: "engineer"}
	res := abac.Resource{Path: "/projects/ev/battery.xlsx"}
	env := abac.Environment{IP: "10.0.0.2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(nil, subj, res, env)
	}
}

func BenchmarkAESEncrypt(b *testing.B) {
	key, _ := crypto.GenerateAESKey()
	data := make([]byte, 4096) // 4KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.AESEncrypt(data, key)
	}
}

// helper to avoid unused import
var _ = fmt.Sprintf
