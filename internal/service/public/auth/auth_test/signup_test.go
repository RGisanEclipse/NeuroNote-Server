package auth_test_test

import (
	"context"
	"os"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSignupService_Signup(t *testing.T) {
	// Set up JWT secret for testing
	err := os.Setenv("JWT_SECRET", "test-secret-key-for-testing")
	if err != nil {
		return
	}

	tests := []struct {
		name           string
		email          string
		password       string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult func(authmodel.ServiceResponse) bool
		expectedError  *appError.Code
	}{
		{
			name:     "Success",
			email:    "test@example.com",
			password: "validPass@1234",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user doesn't exist
				userRepo.On("UserExists", mock.Anything, "test@example.com").Return(false, nil)
				// Mock user creation
				userRepo.On("CreateUser", mock.Anything, "test@example.com", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(true, nil)
				// Mock token storage
				redisRepo.On("SetRefreshToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return result.Success &&
					result.Message == "Account created successfully" &&
					!result.IsVerified &&
					result.AccessToken != "" &&
					result.RefreshToken != ""
			},
			expectedError: mocks.NoError(),
		},
		{
			name:     "EmailAlreadyExists",
			email:    "exists@example.com",
			password: "validPass@1234",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user already exists
				userRepo.On("UserExists", mock.Anything, "exists@example.com").Return(true, nil)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.AuthEmailExists.Message
			},
			expectedError: appError.AuthEmailExists,
		},
		{
			name:     "DatabaseError",
			email:    "test@example.com",
			password: "validPass@1234",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock database error
				userRepo.On("UserExists", mock.Anything, "test@example.com").Return(false, assert.AnError)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.ServerInternalError.Message
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:     "CreateUserFails",
			email:    "test@example.com",
			password: "validPass@1234",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				userRepo.On("UserExists", mock.Anything, "test@example.com").Return(false, nil)
				userRepo.On("CreateUser", mock.Anything, "test@example.com", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(false, assert.AnError)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.ServerInternalError.Message
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:     "RedisTokenStoreFails",
			email:    "test@example.com",
			password: "validPass@1234",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				userRepo.On("UserExists", mock.Anything, "test@example.com").Return(false, nil)
				userRepo.On("CreateUser", mock.Anything, "test@example.com", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(true, nil)
				redisRepo.On("SetRefreshToken", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(assert.AnError)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.ServerInternalError.Message
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

			// Create the actual signup service
			signupSvc := authservice.NewSignupService(userRepo, otpService, redisRepo)

			// Test the service method
			result, errCode := signupSvc.Signup(context.Background(), tt.email, tt.password)

			// Verify results
			assert.True(t, tt.expectedResult(result), "Result validation failed")
			assert.Equal(t, tt.expectedError, errCode, "Error code mismatch")

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			redisRepo.AssertExpectations(t)
			otpService.AssertExpectations(t)
		})
	}
}

func TestSignupService_SignupOTP(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult authmodel.GenericOTPResponse
		expectedError  *appError.Code
	}{
		{
			name:   "Success",
			userId: "user123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("RequestOTP", mock.Anything, "user123", "signup").Return(true, mocks.NoError(), nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			expectedError: mocks.NoError(),
		},
		{
			name:   "OTPServiceReturnsBusinessError",
			userId: "user123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("RequestOTP", mock.Anything, "user123", "signup").Return(false, appError.AuthOtpSendFailure, nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.AuthOtpSendFailure.Message,
			},
			expectedError: appError.AuthOtpSendFailure,
		},
		{
			name:   "OTPServiceReturnsSystemError",
			userId: "user123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("RequestOTP", mock.Anything, "user123", "signup").Return(false, mocks.NoError(), assert.AnError)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: assert.AnError.Error(),
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:   "OTPServiceReturnsFailure",
			userId: "user123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("RequestOTP", mock.Anything, "user123", "signup").Return(false, mocks.NoError(), nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.AuthOtpSendFailure.Message,
			},
			expectedError: appError.AuthOtpSendFailure,
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

			// Create the actual signup service
			signupSvc := authservice.NewSignupService(userRepo, otpService, redisRepo)

			// Test the service method
			result, errCode := signupSvc.SignupOTP(context.Background(), tt.userId)

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

func TestSignupService_SignupOTPVerify(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		code           string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult authmodel.GenericOTPResponse
		expectedError  *appError.Code
	}{
		{
			name:   "Success",
			userId: "user123",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "123456", "signup").Return(true, mocks.NoError(), nil)
				userRepo.On("MarkUserVerified", mock.Anything, "user123").Return(nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			expectedError: mocks.NoError(),
		},
		{
			name:   "InvalidOTP",
			userId: "user123",
			code:   "wrong123",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "wrong123", "signup").Return(false, appError.OtpInvalid, nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.OtpInvalid.Message,
			},
			expectedError: appError.OtpInvalid,
		},
		{
			name:   "OTPExpired",
			userId: "user123",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "123456", "signup").Return(false, appError.OtpExpiredOrNotFound, nil)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.OtpExpiredOrNotFound.Message,
			},
			expectedError: appError.OtpExpiredOrNotFound,
		},
		{
			name:   "SystemError",
			userId: "user123",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "123456", "signup").Return(false, mocks.NoError(), assert.AnError)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: "Internal server error",
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:   "DatabaseUpdateFails",
			userId: "user123",
			code:   "123456",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				otpService.On("VerifyOTP", mock.Anything, "user123", "123456", "signup").Return(true, mocks.NoError(), nil)
				userRepo.On("MarkUserVerified", mock.Anything, "user123").Return(assert.AnError)
			},
			expectedResult: authmodel.GenericOTPResponse{
				Success: false,
				Message: "Failed to mark user as verified",
			},
			expectedError: appError.DBUpdateFailed,
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

			// Create the actual signup service
			signupSvc := authservice.NewSignupService(userRepo, otpService, redisRepo)

			// Test the service method
			result, errCode := signupSvc.SignupOTPVerify(context.Background(), tt.userId, tt.code)

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
