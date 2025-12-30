package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct{ mock.Mock }

func (m *MockAuthService) Signin(ctx context.Context, request authmodel.Request) (authmodel.ServiceResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.ServiceResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, request authmodel.RefreshTokenRequest) (authmodel.RefreshTokenServiceResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.RefreshTokenServiceResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) Signup(ctx context.Context, request authmodel.Request) (authmodel.ServiceResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.ServiceResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) SignupOTP(ctx context.Context, request authmodel.SignupOTPRequest) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) SignupOTPVerify(ctx context.Context, request authmodel.OTPVerifyRequest) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) ForgotPasswordOTP(ctx context.Context, request authmodel.ForgotPasswordOTPRequest) (authmodel.ForgotPasswordOTPResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.ForgotPasswordOTPResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) ForgotPasswordOTPVerify(ctx context.Context, request authmodel.OTPVerifyRequest) (authmodel.ForgotPasswordResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.ForgotPasswordResponse), args.Get(1).(*appError.Code)
}

func (m *MockAuthService) ResetPassword(ctx context.Context, request authmodel.ResetPasswordRequest) (authmodel.ResetPasswordResponse, *appError.Code) {
	args := m.Called(ctx, request)
	return args.Get(0).(authmodel.ResetPasswordResponse), args.Get(1).(*appError.Code)
}
