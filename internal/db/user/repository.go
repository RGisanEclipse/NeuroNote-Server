package user

import "context"

// Creds is a thin DTO returned by the repo
type Creds struct {
	ID           uint
	PasswordHash string
}

// Repository exposes the only methods the auth service needs.
type Repository interface {
	UserExists(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, email, passwordHash string) (uint, error)
	GetUserCreds(ctx context.Context, email string) (*Creds, error)
}