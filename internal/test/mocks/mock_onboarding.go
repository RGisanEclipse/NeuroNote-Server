package mocks

import (
	"context"

	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	"github.com/stretchr/testify/mock"
)

type MockOnboardingRepo struct{ mock.Mock }

func (m *MockOnboardingRepo) SaveOnboardingDetails(ctx context.Context, data om.Model) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockOnboardingRepo) IsOnboardedAlready(ctx context.Context, userID string) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}




