package redis

import (
	"context"
	"time"
)

type Repository interface {
	SetRefreshToken(ctx context.Context, userID uint, token string, expiry time.Duration) error
	GetRefreshToken(ctx context.Context, userID uint) (string, error)
	DeleteRefreshToken(ctx context.Context, userID uint) error
}