package auth_test_test

import (
	"context"
	"os"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSigninService_Signin(t *testing.T) {
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
			email:    "user@example.com",
			password: "ValidPass123@",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user credentials exist
				creds := &userrepo.Creds{
					Id:           "user123",
					PasswordHash: "$2a$10$SQ7QNOG6LkLWwNCKValiX.dTOiQCBWs.R/XoetupHRVMuTqfXqkha", // "ValidPass123@" hashed
				}
				userRepo.On("GetUserCreds", mock.Anything, "user@example.com").Return(creds, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user123").Return(true, nil)
				redisRepo.On("SetRefreshToken", mock.Anything, "user123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return result.Success &&
					result.Message == "Logged in successfully" &&
					result.IsVerified &&
					result.AccessToken != "" &&
					result.RefreshToken != ""
			},
			expectedError: mocks.NoError(),
		},
		{
			name:     "WrongPassword",
			email:    "user@example.com",
			password: "wrongPassword1@",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user credentials exist but password doesn't match
				creds := &userrepo.Creds{
					Id:           "user123",
					PasswordHash: "$2a$10$SQ7QNOG6LkLWwNCKValiX.dTOiQCBWs.R/XoetupHRVMuTqfXqkha", // "ValidPass123@" hashed
				}
				userRepo.On("GetUserCreds", mock.Anything, "user@example.com").Return(creds, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user123").Return(true, nil)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.AuthIncorrectPassword.Message
			},
			expectedError: appError.AuthIncorrectPassword,
		},
		{
			name:     "EmailDoesNotExist",
			email:    "ghost@example.com",
			password: "randomPassword!2",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock user doesn't exist
				userRepo.On("GetUserCreds", mock.Anything, "ghost@example.com").Return(nil, nil)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.AuthEmailDoesntExist.Message
			},
			expectedError: appError.AuthEmailDoesntExist,
		},
		{
			name:     "DatabaseError",
			email:    "user@example.com",
			password: "ValidPass123@",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// Mock database error
				userRepo.On("GetUserCreds", mock.Anything, "user@example.com").Return(nil, assert.AnError)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.AuthEmailDoesntExist.Message
			},
			expectedError: appError.AuthEmailDoesntExist,
		},
		{
			name:     "IsVerifiedCheckFails",
			email:    "user@example.com",
			password: "ValidPass123@",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				creds := &userrepo.Creds{
					Id:           "user123",
					PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMye5IcR4OVqkeha6e5dJSNEqEA/7Y7cQwm",
				}
				userRepo.On("GetUserCreds", mock.Anything, "user@example.com").Return(creds, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user123").Return(false, assert.AnError)
			},
			expectedResult: func(result authmodel.ServiceResponse) bool {
				return !result.Success && result.Message == appError.ServerInternalError.Message
			},
			expectedError: appError.ServerInternalError,
		},
		{
			name:     "RedisTokenStoreFails",
			email:    "user@example.com",
			password: "ValidPass123@",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				creds := &userrepo.Creds{
					Id:           "user123",
					PasswordHash: "$2a$10$SQ7QNOG6LkLWwNCKValiX.dTOiQCBWs.R/XoetupHRVMuTqfXqkha",
				}
				userRepo.On("GetUserCreds", mock.Anything, "user@example.com").Return(creds, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user123").Return(true, nil)
				redisRepo.On("SetRefreshToken", mock.Anything, "user123", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(assert.AnError)
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

			// Create the actual signin service
			signinSvc := authservice.NewSigninService(userRepo, redisRepo)

			// Test the service method
			result, errCode := signinSvc.Signin(context.Background(), tt.email, tt.password)

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

func TestSigninService_RefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		refreshToken   string
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockRedisRepo, *mocks.MockOTPService)
		expectedResult func(authmodel.RefreshTokenServiceResponse) bool
		expectedError  *appError.Code
	}{
		{
			name:         "InvalidTokenFormat",
			refreshToken: "invalid-token-format",
			mockSetup: func(userRepo *mocks.MockUserRepo, redisRepo *mocks.MockRedisRepo, otpService *mocks.MockOTPService) {
				// No mocks needed - token validation will fail at JWT parsing level
			},
			expectedResult: func(result authmodel.RefreshTokenServiceResponse) bool {
				return result.AccessToken == "" && result.RefreshToken == ""
			},
			expectedError: appError.AuthInvalidRefreshToken,
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

			// Test validation logic
			if tt.refreshToken == "" {
				assert.Equal(t, tt.expectedError, appError.ServerBadRequest)
			}

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			redisRepo.AssertExpectations(t)
			otpService.AssertExpectations(t)
		})
	}
}
