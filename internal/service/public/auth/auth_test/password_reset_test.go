package auth_test_test

import (
	"context"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestForgotPasswordService_ForgotPasswordOTP(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult authmodel.GenericOTPResponse
		expectedError  *appError.Code
	}{
		{
			name:  "Success",
			email: "test@example.com",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists
				creds := &userrepo.Creds{Id: "user123", PasswordHash: "hashedpassword"}
				userRepo.On("GetUserCreds", mock.Anything, "test@example.com").Return(creds, nil)
				otpService.On("RequestOTP", mock.Anything, "user123", "forgot_password").Return(true, mocks.NoError(), nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			expectedError: mocks.NoError(),
		},
		{
			name:  "EmailDoesNotExist",
			email: "nonexistent@example.com",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user doesn't exist - need to simulate gorm.ErrRecordNotFound
				userRepo.On("GetUserCreds", mock.Anything, "nonexistent@example.com").Return(nil, assert.AnError)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:  "DatabaseError",
			email: "test@example.com",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock database error
				userRepo.On("GetUserCreds", mock.Anything, "test@example.com").Return(nil, assert.AnError)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:  "OTPServiceReturnsBusinessError",
			email: "test@example.com",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				creds := &userrepo.Creds{Id: "user123", PasswordHash: "hashedpassword"}
				userRepo.On("GetUserCreds", mock.Anything, "test@example.com").Return(creds, nil)
				otpService.On("RequestOTP", mock.Anything, "user123", "forgot_password").Return(false, appError.AuthOtpSendFailure, nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.AuthOtpSendFailure.Message,
			},
			expectedError: appError.AuthOtpSendFailure,
		},
		{
			name:  "OTPServiceReturnsSystemError",
			email: "test@example.com",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				creds := &userrepo.Creds{Id: "user123", PasswordHash: "hashedpassword"}
				userRepo.On("GetUserCreds", mock.Anything, "test@example.com").Return(creds, nil)
				otpService.On("RequestOTP", mock.Anything, "user123", "forgot_password").Return(false, mocks.NoError(), assert.AnError)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectedError: appError.ServerInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := new(mocks.MockUserRepo)
			redisRepo := new(mocks.MockRedisRepo)
			otpService := new(mocks.MockOTPService)

			// Setup mocks
			tt.mockSetup(userRepo, redisRepo, otpService)

			// Create the actual forgot password service
			forgotPasswordSvc := authservice.NewForgotPasswordService(userRepo, otpService, redisRepo)

			// Test the service method
			result, errCode := forgotPasswordSvc.ForgotPasswordOTP(context.Background(), tt.email)

			// Verify results
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedError, errCode)

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			redisRepo.AssertExpectations(t)
			otpService.AssertExpectations(t)
		})
	}
}

func TestForgotPasswordService_ForgotPasswordOTPVerify(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		code           string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult authmodel.ForgotPasswordResponse
		expectedError  *appError.Code
	}{
		{
			name:   "Success",
			userId: "user123",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "123456", "forgot_password").Return(true, mocks.NoError(), nil)
				// Mock setting verification flag in Redis
				redisRepo.On("SetPasswordResetFlag", mock.Anything, "user123", mock.AnythingOfType("time.Duration")).Return(nil)
			},
			expectedResult: authmodel.ForgotPasswordResponse{
				Success: true,
				Message: "OTP verified successfully",
				UserId:  "user123",
			},
			expectedError: mocks.NoError(),
		},
		{
			name:   "InvalidOTP",
			userId: "user123",
			code:   "wrong123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "wrong123", "forgot_password").Return(false, appError.OtpInvalid, nil)
			},
			expectedResult: authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.OtpInvalid.Message,
			},
			expectedError: appError.OtpInvalid,
		},
		{
			name:   "OTPExpiredOrNotFound",
			userId: "user123",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "123456", "forgot_password").Return(false, appError.OtpExpiredOrNotFound, nil)
			},
			expectedResult: authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.OtpExpiredOrNotFound.Message,
			},
			expectedError: appError.OtpExpiredOrNotFound,
		},
		{
			name:   "EmptyUserId",
			userId: "",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// No mocks needed for validation errors
			},
			expectedResult: authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectedError: appError.ServerBadRequest,
		},
		{
			name:   "EmptyCode",
			userId: "user123",
			code:   "",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// No mocks needed for validation errors
			},
			expectedResult: authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectedError: appError.ServerBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := new(mocks.MockUserRepo)
			redisRepo := new(mocks.MockRedisRepo)
			otpService := new(mocks.MockOTPService)

			// Setup mocks
			tt.mockSetup(userRepo, redisRepo, otpService)

			// Create the actual forgot password service
			forgotPasswordSvc := authservice.NewForgotPasswordService(userRepo, otpService, redisRepo)

			// Test the service method
			result, errCode := forgotPasswordSvc.ForgotPasswordOTPVerify(context.Background(), tt.userId, tt.code)

			// Verify results
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedError, errCode)

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			redisRepo.AssertExpectations(t)
			otpService.AssertExpectations(t)
		})
	}
}

func TestForgotPasswordService_ResetPassword(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		password       string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult authmodel.ResetPasswordResponse
		expectedError  *appError.Code
	}{
		{
			name:     "Success",
			userId:   "user1234567890",
			password: "NewPassword123!",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists check
				userRepo.On("UserExists", mock.Anything, "user1234567890").Return(true, nil)
				// Mock OTP verification check
				redisRepo.On("CheckPasswordResetFlag", mock.Anything, "user1234567890").Return(true, nil)
				// Mock user password reset
				userRepo.On("ResetPassword", mock.Anything, "user1234567890", mock.AnythingOfType("string")).Return(nil)
				// Mock cleanup
				redisRepo.On("DeletePasswordResetFlag", mock.Anything, "user1234567890").Return(nil)
			},
			expectedResult: authmodel.ResetPasswordResponse{
				Success: true,
				Message: "Password Reset successfully",
			},
			expectedError: mocks.NoError(),
		},
		{
			name:     "OTPNotVerified",
			userId:   "user1234567890",
			password: "newpassword123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists check
				userRepo.On("UserExists", mock.Anything, "user1234567890").Return(true, nil)
				// Mock OTP verification check fails
				redisRepo.On("CheckPasswordResetFlag", mock.Anything, "user1234567890").Return(false, nil)
			},
			expectedResult: authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.AuthPasswordOtpNotVerified.Message,
			},
			expectedError: appError.AuthPasswordOtpNotVerified,
		},
		{
			name:     "EmptyUserId",
			userId:   "",
			password: "newpassword123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists check for empty userId
				userRepo.On("UserExists", mock.Anything, "").Return(false, nil)
			},
			expectedResult: authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.AuthUserNotFound.Message,
			},
			expectedError: appError.AuthUserNotFound,
		},
		{
			name:     "InvalidUserIdLength",
			userId:   "short",
			password: "newpassword123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists check for short userId
				userRepo.On("UserExists", mock.Anything, "short").Return(false, nil)
			},
			expectedResult: authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.AuthUserNotFound.Message,
			},
			expectedError: appError.AuthUserNotFound,
		},
		{
			name:     "WeakPassword",
			userId:   "user1234567890",
			password: "weak",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists check
				userRepo.On("UserExists", mock.Anything, "user1234567890").Return(true, nil)
				// Mock OTP verification check
				redisRepo.On("CheckPasswordResetFlag", mock.Anything, "user1234567890").Return(true, nil)
			},
			expectedResult: authmodel.ResetPasswordResponse{
				Success: false,
				Message: "Password doesn't match the required criteria",
			},
			expectedError: appError.PasswordTooShort,
		},
		{
			name:     "RedisFlagCheckFailed",
			userId:   "user1234567890",
			password: "newpassword123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user exists check
				userRepo.On("UserExists", mock.Anything, "user1234567890").Return(true, nil)
				// Mock Redis error
				redisRepo.On("CheckPasswordResetFlag", mock.Anything, "user1234567890").Return(false, assert.AnError)
			},
			expectedResult: authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectedError: appError.ServerInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := new(mocks.MockUserRepo)
			redisRepo := new(mocks.MockRedisRepo)
			otpService := new(mocks.MockOTPService)

			// Setup mocks
			tt.mockSetup(userRepo, redisRepo, otpService)

			// Create the actual forgot password service
			forgotPasswordSvc := authservice.NewForgotPasswordService(userRepo, otpService, redisRepo)

			// Test the service method
			result, errCode := forgotPasswordSvc.ResetPassword(context.Background(), tt.userId, tt.password)

			// Verify results
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedError, errCode)

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			redisRepo.AssertExpectations(t)
			otpService.AssertExpectations(t)
		})
	}
}
