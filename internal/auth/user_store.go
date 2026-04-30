package auth

import (
	"sync"
)

type User struct {
	ID         string
	Password   string // 明文密码（演示用）
	Role       string
	Project    string
	TOTPSecret string // MFA 密钥
	MFAEnabled bool
}

type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User
}

func NewUserStore() *UserStore {
	store := &UserStore{
		users: make(map[string]*User),
	}
	// 添加测试用户
	store.users["alice"] = &User{
		ID:         "alice",
		Password:   "password123",
		Role:       "engineer",
		Project:    "ev_project",
		MFAEnabled: false,
	}
	store.users["admin"] = &User{
		ID:         "admin",
		Password:   "admin123",
		Role:       "admin",
		Project:    "",
		MFAEnabled: false,
	}
	return store
}

func (s *UserStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

func (s *UserStore) SetTOTPSecret(username, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[username]; ok {
		u.TOTPSecret = secret
		u.MFAEnabled = true
	}
}
