package mocks

import (
	"context"

	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/stretchr/testify/mock"
)

type MockUserRepo struct{ mock.Mock }

func (m *MockUserRepo) UserExists(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) UserExistsById(ctx context.Context, userId string) (bool, error) {
	args := m.Called(ctx, userId)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) CreateUser(ctx context.Context, email, passwordHash, userId string) (bool, error) {
	args := m.Called(ctx, email, passwordHash, userId)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) GetUserCreds(ctx context.Context, email string) (*userrepo.Creds, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*userrepo.Creds), args.Error(1)
}

func (m *MockUserRepo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	args := m.Called(ctx, userId)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) GetUserEmailById(ctx context.Context, userId string) (string, error) {
	args := m.Called(ctx, userId)
	return args.String(0), args.Error(1)
}

func (m *MockUserRepo) MarkUserVerified(ctx context.Context, userId string) error {
	args := m.Called(ctx, userId)
	return args.Error(0)
}

func (m *MockUserRepo) ResetPassword(ctx context.Context, userId, password string) error {
	args := m.Called(ctx, userId, password)
	return args.Error(0)
}
