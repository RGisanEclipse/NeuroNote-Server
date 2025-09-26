package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
)

type MockRedisRepo struct{ mock.Mock }

func (m *MockRedisRepo) SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	args := m.Called(ctx, userID, token, expiry)
	return args.Error(0)
}

func (m *MockRedisRepo) GetRefreshToken(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockRedisRepo) DeleteRefreshToken(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRedisRepo) SetOTP(ctx context.Context, userId string, otp string, ttl time.Duration, purpose string) error {
	args := m.Called(ctx, userId, otp, ttl, purpose)
	return args.Error(0)
}

func (m *MockRedisRepo) GetOTP(ctx context.Context, userId string, purpose string) (string, error) {
	args := m.Called(ctx, userId, purpose)
	return args.String(0), args.Error(1)
}

func (m *MockRedisRepo) DeleteOTP(ctx context.Context, userId string, purpose string) error {
	args := m.Called(ctx, userId, purpose)
	return args.Error(0)
}

func (m *MockRedisRepo) SetPasswordResetFlag(ctx context.Context, userId string, ttl time.Duration) error {
	args := m.Called(ctx, userId, ttl)
	return args.Error(0)
}

func (m *MockRedisRepo) CheckPasswordResetFlag(ctx context.Context, userId string) (bool, error) {
	args := m.Called(ctx, userId)
	return args.Bool(0), args.Error(1)
}

func (m *MockRedisRepo) DeletePasswordResetFlag(ctx context.Context, userId string) error {
	args := m.Called(ctx, userId)
	return args.Error(0)
}

func (m *MockRedisRepo) GetPasswordResetKey(userId string) string {
	args := m.Called(userId)
	return args.String(0)
}
