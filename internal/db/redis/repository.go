package redis

import (
	"context"
	"time"
)

type Repository interface {
	SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error
	GetRefreshToken(ctx context.Context, userID string) (string, error)
	DeleteRefreshToken(ctx context.Context, userID string) error

	SetOTP(ctx context.Context, userId string, otp string, ttl time.Duration, purpose string) error
	GetOTP(ctx context.Context, userId string, purpose string) (string, error)
	DeleteOTP(ctx context.Context, userId string, purpose string) error

	SetPasswordResetFlag(ctx context.Context, userId string, ttl time.Duration) error
	CheckPasswordResetFlag(ctx context.Context, userId string) (bool, error)
	DeletePasswordResetFlag(ctx context.Context, userId string) error
	GetPasswordResetKey(userId string) string
}
