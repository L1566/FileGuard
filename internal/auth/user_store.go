package auth

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// User 表示系统中的用户账户
type User struct {
	ID         string
	Password   string // bcrypt 哈希
	Role       string
	Project    string
	TOTPSecret string // MFA 密钥（Base32）
	MFAEnabled bool   // MFA 是否已通过验证并启用
}

// UserStore 线程安全的内存用户存储（演示用途，生产应使用数据库）
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
}

// NewUserStore 创建用户存储并初始化测试用户
func NewUserStore() *UserStore {
	store := &UserStore{
		users: make(map[string]*User),
	}

	// 预哈希测试用户密码（生产应从数据库加载）
	aliceHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)

	store.users["alice"] = &User{
		ID:         "alice",
		Password:   string(aliceHash),
		Role:       "engineer",
		Project:    "ev_project",
		MFAEnabled: false,
	}
	store.users["admin"] = &User{
		ID:         "admin",
		Password:   string(adminHash),
		Role:       "admin",
		Project:    "",
		MFAEnabled: false,
	}
	return store
}

// GetUser 按用户名获取用户（线程安全）
func (s *UserStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

// VerifyPassword 验证用户密码
func (s *UserStore) VerifyPassword(username, password string) bool {
	u, ok := s.GetUser(username)
	if !ok {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

// SetPassword 设置/修改用户密码（自动 bcrypt 哈希）
func (s *UserStore) SetPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[username]; ok {
		u.Password = string(hash)
	}
	return nil
}

// SetTOTPSecret 保存 TOTP 密钥（仅保存，不启用 MFA——需 VerifyMFA 验证后才启用）
func (s *UserStore) SetTOTPSecret(username, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[username]; ok {
		u.TOTPSecret = secret
		// 注意：此处不设置 MFAEnabled = true
		// 用户必须通过 VerifyMFA 成功验证一次后才启用
	}
}

// EnableMFA 在用户成功验证 TOTP 后启用 MFA
func (s *UserStore) EnableMFA(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[username]; ok {
		if u.TOTPSecret != "" {
			u.MFAEnabled = true
			return true
		}
	}
	return false
}
