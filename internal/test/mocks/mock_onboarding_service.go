package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	"github.com/stretchr/testify/mock"
)

type MockOnboardingService struct{ mock.Mock }

func (m *MockOnboardingService) OnboardUser(ctx context.Context, userId string, onboardingData om.Model) (bool, *appError.Code) {
	args := m.Called(ctx, userId, onboardingData)
	return args.Bool(0), args.Get(1).(*appError.Code)
}
