package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/stretchr/testify/mock"
)

type MockOTPService struct{ mock.Mock }

func (m *MockOTPService) RequestOTP(ctx context.Context, userID string, purpose string) (bool, *appError.Code, error) {
	args := m.Called(ctx, userID, purpose)
	return args.Bool(0), args.Get(1).(*appError.Code), args.Error(2)
}

func (m *MockOTPService) VerifyOTP(ctx context.Context, userID string, code string, purpose string) (bool, *appError.Code, error) {
	args := m.Called(ctx, userID, code, purpose)
	return args.Bool(0), args.Get(1).(*appError.Code), args.Error(2)
}
