package redis

import (
	"context"
	"time"
)

type Repository interface {
	SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error
	GetRefreshToken(ctx context.Context, userID string) (string, error)
	DeleteRefreshToken(ctx context.Context, userID string) error
	// OTPService Methods
	SetOTP(ctx context.Context, key string, otp string, ttl time.Duration) error
	GetOTP(ctx context.Context, key string) (string, error)
	DeleteOTP(ctx context.Context, key string) error
}