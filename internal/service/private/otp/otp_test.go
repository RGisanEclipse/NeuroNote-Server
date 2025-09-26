package otp

import (
	"context"
	"errors"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRequestOTP(t *testing.T) {
	tests := []struct {
		name            string
		userID          string
		purpose         string
		email           string
		emailError      error
		redisError      error
		emailSendError  error
		expectedSuccess bool
		expectedError   string
		expectSetOTP    bool
		expectGetEmail  bool
		expectSendMail  bool
	}{
		{
			name:            "Success_Signup",
			userID:          "user123",
			purpose:         "signup",
			email:           "test@example.com",
			expectedSuccess: true,
			expectSetOTP:    true,
			expectGetEmail:  true,
			expectSendMail:  true,
		},
		{
			name:            "Success_ForgotPassword",
			userID:          "user456",
			purpose:         "forgot_password",
			email:           "user@example.com",
			expectedSuccess: true,
			expectSetOTP:    true,
			expectGetEmail:  true,
			expectSendMail:  true,
		},
		{
			name:            "Fails_WhenRedisSetOTPFails",
			userID:          "user123",
			purpose:         "signup",
			email:           "test@example.com",
			redisError:      errors.New("redis connection failed"),
			expectedSuccess: false,
			expectedError:   "redis connection failed",
			expectSetOTP:    true,
		},
		{
			name:            "Fails_WhenDBQueryFails",
			userID:          "user123",
			purpose:         "signup",
			emailError:      errors.New("database connection failed"),
			expectedSuccess: false,
			expectedError:   "database connection failed",
			expectSetOTP:    true,
			expectGetEmail:  true,
		},
		{
			name:            "Fails_WhenEmptyEmailReturned",
			userID:          "user123",
			purpose:         "signup",
			email:           "",
			expectedSuccess: false,
			expectedError:   appError.OtpEmptyEmailForUser.Message,
			expectSetOTP:    true,
			expectGetEmail:  true,
		},
		{
			name:            "Fails_WhenEmailSendFails",
			userID:          "user123",
			purpose:         "signup",
			email:           "test@example.com",
			emailSendError:  errors.New("email service unavailable"),
			expectedSuccess: false,
			expectedError:   "email service unavailable",
			expectSetOTP:    true,
			expectGetEmail:  true,
			expectSendMail:  true,
		},
		{
			name:            "Fails_WhenPurposeIsInvalid",
			userID:          "user123",
			purpose:         "invalid_purpose",
			expectedSuccess: false,
			expectedError:   appError.OtpInvalidPurpose.Message,
		},
		{
			name:            "Fails_WhenUserIDIsEmpty",
			userID:          "",
			purpose:         "signup",
			email:           "",
			expectedSuccess: false,
			expectedError:   appError.OtpEmptyEmailForUser.Message,
			expectSetOTP:    true,
			expectGetEmail:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mocks.MockUserRepo)
			mockRedisRepo := new(mocks.MockRedisRepo)
			mockPhoenixService := new(mocks.MockPhoenixService)

			service := New(mockUserRepo, mockRedisRepo, mockPhoenixService)
			ctx := context.Background()

			if tt.expectSetOTP {
				mockRedisRepo.On("SetOTP", ctx, tt.userID, mock.AnythingOfType("string"), mock.Anything, tt.purpose).
					Return(tt.redisError)
			}
			if tt.expectGetEmail {
				mockUserRepo.On("GetUserEmailById", ctx, tt.userID).
					Return(tt.email, tt.emailError)
			}
			if tt.expectSendMail {
				mockPhoenixService.On("SendMail", ctx, tt.userID, mock.Anything).
					Return(tt.emailSendError)
			}

			success, errCode, err := service.RequestOTP(ctx, tt.userID, tt.purpose)

			assert.Equal(t, tt.expectedSuccess, success)

			if tt.expectedError != "" {
				if err != nil {
					assert.EqualError(t, err, tt.expectedError)
				} else if errCode != nil {
					assert.Equal(t, tt.expectedError, errCode.Message)
				} else {
					t.Errorf("expected error but got none")
				}
			} else {
				assert.NoError(t, err)
				assert.Nil(t, errCode)
			}

			mockRedisRepo.AssertExpectations(t)
			mockUserRepo.AssertExpectations(t)
			mockPhoenixService.AssertExpectations(t)
		})
	}
}

func TestVerifyOTP(t *testing.T) {
	tests := []struct {
		name            string
		userID          string
		code            string
		purpose         string
		storedOTP       string
		redisGetError   error
		deleteOTPErr    error
		expectedSuccess bool
		expectedError   string
	}{
		{
			name:            "Succeeds_WhenOTPMatches",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "123456",
			expectedSuccess: true,
		},
		{
			name:          "Fails_WhenOTPDoesNotMatch",
			userID:        "user123",
			code:          "000000",
			purpose:       "signup",
			storedOTP:     "123456",
			expectedError: appError.OtpInvalid.Message,
		},
		{
			name:          "Fails_WhenOTPExpiredOrNotFound",
			userID:        "user123",
			code:          "123456",
			purpose:       "signup",
			storedOTP:     "",
			expectedError: appError.OtpExpiredOrNotFound.Message,
		},
		{
			name:          "Fails_WhenRedisGetFails",
			userID:        "user123",
			code:          "123456",
			purpose:       "signup",
			redisGetError: errors.New("redis down"),
			expectedError: "redis down",
		},
		{
			name:          "Fails_WhenPurposeIsInvalid",
			userID:        "user123",
			code:          "123456",
			purpose:       "invalid_purpose",
			expectedError: appError.OtpInvalidPurpose.Message,
		},
		{
			name:            "Succeeds_WhenOTPHasLeadingZeros",
			userID:          "user123",
			code:            "000123",
			purpose:         "signup",
			storedOTP:       "000123",
			expectedSuccess: true,
		},
		{
			name:            "Succeeds_WhenDeleteOTPFails",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "123456",
			deleteOTPErr:    errors.New("redis delete failed"),
			expectedSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mocks.MockUserRepo)
			mockRedisRepo := new(mocks.MockRedisRepo)
			mockPhoenixService := new(mocks.MockPhoenixService)

			service := New(mockUserRepo, mockRedisRepo, mockPhoenixService)
			ctx := context.Background()

			mockRedisRepo.On("GetOTP", ctx, tt.userID, tt.purpose).
				Return(tt.storedOTP, tt.redisGetError).Maybe()

			mockRedisRepo.On("DeleteOTP", ctx, tt.userID, tt.purpose).
				Return(tt.deleteOTPErr).Maybe()

			success, errCode, err := service.VerifyOTP(ctx, tt.userID, tt.code, tt.purpose)

			assert.Equal(t, tt.expectedSuccess, success)

			if tt.expectedError != "" {
				if err != nil {
					assert.EqualError(t, err, tt.expectedError)
				} else if errCode != nil {
					assert.Equal(t, tt.expectedError, errCode.Message)
				} else {
					t.Errorf("expected error but got none")
				}
			} else {
				assert.NoError(t, err)
				assert.Nil(t, errCode)
			}

			mockRedisRepo.AssertExpectations(t)
		})
	}
}
