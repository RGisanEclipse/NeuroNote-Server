package user

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockRepo is a mock implementation of the user Repository interface
type MockRepo struct {
	mock.Mock
}

// UserExists mocks checking if a user exists by email
func (m *MockRepo) UserExists(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

// CreateUser mocks creating a new user
func (m *MockRepo) CreateUser(ctx context.Context, email, passwordHash, userId string) (bool, error) {
	args := m.Called(ctx, email, passwordHash, userId)
	return args.Bool(0), args.Error(1)
}

// GetUserCreds mocks getting user credentials by email
func (m *MockRepo) GetUserCreds(ctx context.Context, email string) (*Creds, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*Creds), args.Error(1)
}

// IsUserVerified mocks checking if a user is verified
func (m *MockRepo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	args := m.Called(ctx, userId)
	return args.Bool(0), args.Error(1)
}

// GetUserEmailById mocks getting user email by ID
func (m *MockRepo) GetUserEmailById(ctx context.Context, userId string) (string, error) {
	args := m.Called(ctx, userId)
	return args.String(0), args.Error(1)
}

// MarkUserVerified mocks marking a user as verified
func (m *MockRepo) MarkUserVerified(ctx context.Context, userId string) error {
	args := m.Called(ctx, userId)
	return args.Error(0)
}

// ResetPassword mocks resetting a user's password
func (m *MockRepo) ResetPassword(ctx context.Context, userId, password string) error {
	args := m.Called(ctx, userId, password)
	return args.Error(0)
}