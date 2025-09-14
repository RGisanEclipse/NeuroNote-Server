package redis

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
)

// MockRedisRepo is a mock implementation of the redis Repository interface
type MockRedisRepo struct {
	mock.Mock
}

// SetRefreshToken mocks setting a refresh token in Redis
func (m *MockRedisRepo) SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	args := m.Called(ctx, userID, token, expiry)
	return args.Error(0)
}

// GetRefreshToken mocks getting a refresh token from Redis
func (m *MockRedisRepo) GetRefreshToken(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

// DeleteRefreshToken mocks deleting a refresh token from Redis
func (m *MockRedisRepo) DeleteRefreshToken(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// SetOTP mocks setting an OTP in Redis
func (m *MockRedisRepo) SetOTP(ctx context.Context, userId string, otp string, ttl time.Duration, purpose string) error {
	args := m.Called(ctx, userId, otp, ttl, purpose)
	return args.Error(0)
}

// GetOTP mocks getting an OTP from Redis
func (m *MockRedisRepo) GetOTP(ctx context.Context, userId string, purpose string) (string, error) {
	args := m.Called(ctx, userId, purpose)
	return args.String(0), args.Error(1)
}

// DeleteOTP mocks deleting an OTP from Redis
func (m *MockRedisRepo) DeleteOTP(ctx context.Context, userId string, purpose string) error {
	args := m.Called(ctx, userId, purpose)
	return args.Error(0)
}

// SetPasswordResetFlag mocks setting a password reset flag in Redis
func (m *MockRedisRepo) SetPasswordResetFlag(ctx context.Context, userId string, ttl time.Duration) error {
	args := m.Called(ctx, userId, ttl)
	return args.Error(0)
}

// CheckPasswordResetFlag mocks checking if a password reset flag exists in Redis
func (m *MockRedisRepo) CheckPasswordResetFlag(ctx context.Context, userId string) (bool, error) {
	args := m.Called(ctx, userId)
	return args.Bool(0), args.Error(1)
}

// DeletePasswordResetFlag mocks deleting a password reset flag from Redis
func (m *MockRedisRepo) DeletePasswordResetFlag(ctx context.Context, userId string) error {
	args := m.Called(ctx, userId)
	return args.Error(0)
}

// GetPasswordResetKey mocks generating a password reset key
func (m *MockRedisRepo) GetPasswordResetKey(userId string) string {
	args := m.Called(userId)
	return args.String(0)
}
