package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct{ mock.Mock }

func (m *MockAuthService) Signin(ctx context.Context, email, pw string) (authmodel.ServiceResponse, *appError.Code) {
	args := m.Called(ctx, email, pw)
	return args.Get(0).(authmodel.ServiceResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (authmodel.RefreshTokenServiceResponse, *appError.Code) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(authmodel.RefreshTokenServiceResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) Signup(ctx context.Context, email, pw string) (authmodel.ServiceResponse, *appError.Code) {
	args := m.Called(ctx, email, pw)
	return args.Get(0).(authmodel.ServiceResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) SignupOTP(ctx context.Context, userId string) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, userId)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) SignupOTPVerify(ctx context.Context, userId, code string) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, userId, code)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) ForgotPasswordOTP(ctx context.Context, email string) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, email)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) ForgotPasswordOTPVerify(ctx context.Context, userId, code string) (authmodel.ForgotPasswordResponse, *appError.Code) {
	args := m.Called(ctx, userId, code)
	return args.Get(0).(authmodel.ForgotPasswordResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) ResetPassword(ctx context.Context, userId, password string) (authmodel.ResetPasswordResponse, *appError.Code) {
	args := m.Called(ctx, userId, password)
	return args.Get(0).(authmodel.ResetPasswordResponse), args.Get(1).(*appError.Code)
}
