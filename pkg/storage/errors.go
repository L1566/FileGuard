package storage

import "errors"

var (
	ErrNotFound      = errors.New("file not found")
	ErrPermission    = errors.New("permission denied")
	ErrAlreadyExists = errors.New("file already exists")
)
