// internal/db/user/mock_repo.go
package user

import (
	"context"
)

type MockRepo struct {
	UserExistsFn   func(ctx context.Context, email string) (bool, error)
	CreateUserFn   func(ctx context.Context, email, hash string) (uint, error)
	GetUserCredsFn func(ctx context.Context, email string) (uint, string, error)
}

func (m *MockRepo) UserExists(ctx context.Context, email string) (bool, error) {
	return m.UserExistsFn(ctx, email)
}

func (m *MockRepo) CreateUser(ctx context.Context, email, hash string) (uint, error) {
	return m.CreateUserFn(ctx, email, hash)
}

func (m *MockRepo) GetUserCreds(ctx context.Context, email string) (uint, string, error) {
	return m.GetUserCredsFn(ctx, email)
}