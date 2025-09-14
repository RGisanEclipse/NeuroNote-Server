// internal/db/user/mock_repo.go
package user

import (
	"context"
)

type MockRepo struct {
	UserExistsFn       func(ctx context.Context, email string) (bool, error)
	CreateUserFn       func(ctx context.Context, email, hash, userId string) (uint, error)
	GetUserCredsFn     func(ctx context.Context, email string) (uint, string, error)
	IsUserVerifiedFn   func(ctx context.Context, userId string) (bool, error)
	GetUserEmailByIdFn func(ctx context.Context, userId string) (string, error)
	MarkUserVerifiedFn func(ctx context.Context, userId string) error
	ResetPasswordFn    func(ctx context.Context, userId, password string) error
}

func (m *MockRepo) UserExists(ctx context.Context, email string) (bool, error) {
	return m.UserExistsFn(ctx, email)
}

func (m *MockRepo) CreateUser(ctx context.Context, email, hash, userId string) (uint, error) {
	return m.CreateUserFn(ctx, email, hash, userId)
}

func (m *MockRepo) GetUserCreds(ctx context.Context, email string) (uint, string, error) {
	return m.GetUserCredsFn(ctx, email)
}

func (m *MockRepo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	return m.IsUserVerifiedFn(ctx, userId)
}

func (m *MockRepo) GetUserEmailById(ctx context.Context, userId string) (string, error) {
	return m.GetUserEmailByIdFn(ctx, userId)
}

func (m *MockRepo) MarkUserVerified(ctx context.Context, userId string) error {
	return m.MarkUserVerifiedFn(ctx, userId)
}

func (m *MockRepo) ResetPassword(ctx context.Context, userId, password string) error {
	return m.ResetPassword(ctx, userId, password)
}
