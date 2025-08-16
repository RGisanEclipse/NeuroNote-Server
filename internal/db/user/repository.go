package user

import "context"

// Creds is a thin DTO returned by the repo
type Creds struct {
	Id           string
	PasswordHash string
}

// Repository exposes the only methods the auth service needs.
type Repository interface {
	UserExists(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, email, passwordHash, userId string) (bool, error)
	GetUserCreds(ctx context.Context, email string) (*Creds, error)
	IsUserVerified(ctx context.Context, userId string) (bool, error)
	GetUserEmailById(ctx context.Context, userId string) (string, error)
}