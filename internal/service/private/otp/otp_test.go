package otp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
)

// Mock dependencies
type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) UserExists(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) CreateUser(ctx context.Context, email, passwordHash, userId string) (bool, error) {
	args := m.Called(ctx, email, passwordHash, userId)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) GetUserCreds(ctx context.Context, email string) (*userrepo.Creds, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*userrepo.Creds), args.Error(1)
}

func (m *MockUserRepo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	args := m.Called(ctx, userId)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) GetUserEmailById(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockUserRepo) MarkUserVerified(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}


type MockRedisRepo struct {
	mock.Mock
}

func (m *MockRedisRepo) SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	args := m.Called(ctx, userID, token, expiry)
	return args.Error(0)
}

func (m *MockRedisRepo) GetRefreshToken(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockRedisRepo) DeleteRefreshToken(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRedisRepo) SetOTP(ctx context.Context, userID string, otp string, ttl time.Duration, purpose string) error {
	args := m.Called(ctx, userID, otp, ttl, purpose)
	return args.Error(0)
}

func (m *MockRedisRepo) GetOTP(ctx context.Context, userID string, purpose string) (string, error) {
	args := m.Called(ctx, userID, purpose)
	return args.String(0), args.Error(1)
}

func (m *MockRedisRepo) DeleteOTP(ctx context.Context, userID string, purpose string) error {
	args := m.Called(ctx, userID, purpose)
	return args.Error(0)
}

type MockPhoenixService struct {
	mock.Mock
}

func (m *MockPhoenixService) SendMail(ctx context.Context, userID string, template phoenix.EmailTemplate) error {
	args := m.Called(ctx, userID, template)
	return args.Error(0)
}

func TestRequestOTP(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		purpose        string
		email          string
		emailError     error
		redisError     error
		emailSendError error
		expectedSuccess bool
		expectedError  string
		expectSetOTP   bool
		expectGetEmail bool
		expectSendMail bool
	}{
		{
			name:           "Success_Signup",
			userID:         "user123",
			purpose:        "signup",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
		{
			name:           "Success_ForgotPassword",
			userID:         "user456",
			purpose:        "forgot_password",
			email:          "user@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
		{
			name:           "RedisError",
			userID:         "user123",
			purpose:        "signup",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     errors.New("redis connection failed"),
			emailSendError: nil,
			expectedSuccess: false,
			expectedError:  "internal server error",
			expectSetOTP:   true,
			expectGetEmail: false,
			expectSendMail: false,
		},
		{
			name:           "EmailQueryError",
			userID:         "user123",
			purpose:        "signup",
			email:          "",
			emailError:     errors.New("database connection failed"),
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: false,
			expectedError:  "internal server error",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: false,
		},
		{
			name:           "EmptyEmail",
			userID:         "user123",
			purpose:        "signup",
			email:          "",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: false,
			expectedError:  "internal server error",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: false,
		},
		{
			name:           "EmailSendError",
			userID:         "user123",
			purpose:        "signup",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: errors.New("email service unavailable"),
			expectedSuccess: false,
			expectedError:  "internal server error",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepo)
			mockRedisRepo := new(MockRedisRepo)
			mockPhoenixService := new(MockPhoenixService)

			service := New(mockUserRepo, mockRedisRepo, mockPhoenixService)
			ctx := context.Background()

			// Setup mocks based on expectations
			if tt.expectSetOTP {
				mockRedisRepo.On("SetOTP", ctx, tt.userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration"), tt.purpose).Return(tt.redisError)
			}

			if tt.expectGetEmail {
				mockUserRepo.On("GetUserEmailById", ctx, tt.userID).Return(tt.email, tt.emailError)
			}

			if tt.expectSendMail {
				mockPhoenixService.On("SendMail", ctx, tt.userID, mock.AnythingOfType("phoenix.EmailTemplate")).Return(tt.emailSendError)
			}

			// Execute
			success, err := service.RequestOTP(ctx, tt.userID, tt.purpose)

			// Assertions
			assert.Equal(t, tt.expectedSuccess, success)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			if tt.expectSetOTP {
				mockRedisRepo.AssertExpectations(t)
			}
			if tt.expectGetEmail {
				mockUserRepo.AssertExpectations(t)
			}
			if tt.expectSendMail {
				mockPhoenixService.AssertExpectations(t)
			}
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
		expectedSuccess bool
		expectedError   string
		expectGetOTP    bool
		expectDeleteOTP bool
	}{
		{
			name:            "Success_Signup",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: true,
			expectedError:   "",
			expectGetOTP:    true,
			expectDeleteOTP: true,
		},
		{
			name:            "Success_ForgotPassword",
			userID:          "user456",
			code:            "789012",
			purpose:         "forgot_password",
			storedOTP:       "789012",
			redisGetError:   nil,
			expectedSuccess: true,
			expectedError:   "",
			expectGetOTP:    true,
			expectDeleteOTP: true,
		},
		{
			name:            "RedisGetError",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "",
			redisGetError:   errors.New("redis connection failed"),
			expectedSuccess: false,
			expectedError:   "internal server error",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "OTPExpiredOrNotFound",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "", // Empty OTP means expired/not found
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "otp expired or not found",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "InvalidOTP",
			userID:          "user123",
			code:            "654321", // Wrong code
			purpose:         "signup",
			storedOTP:       "123456", // Correct OTP
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "invalid otp",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "CaseSensitiveOTP",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "123456", // Exact match
			redisGetError:   nil,
			expectedSuccess: true,
			expectedError:   "",
			expectGetOTP:    true,
			expectDeleteOTP: true,
		},
		{
			name:            "EmptyCode",
			userID:          "user123",
			code:            "", // Empty code
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "invalid otp",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "WhitespaceInCode",
			userID:          "user123",
			code:            " 123456 ", // Code with whitespace
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "invalid otp",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepo)
			mockRedisRepo := new(MockRedisRepo)
			mockPhoenixService := new(MockPhoenixService)

			service := New(mockUserRepo, mockRedisRepo, mockPhoenixService)
			ctx := context.Background()

			// Setup mocks based on expectations
			if tt.expectGetOTP {
				mockRedisRepo.On("GetOTP", ctx, tt.userID, tt.purpose).Return(tt.storedOTP, tt.redisGetError)
			}

			if tt.expectDeleteOTP {
				mockRedisRepo.On("DeleteOTP", ctx, tt.userID, tt.purpose).Return(nil)
			}


			// Execute
			success, err := service.VerifyOTP(ctx, tt.userID, tt.code, tt.purpose)

			// Assertions
			assert.Equal(t, tt.expectedSuccess, success)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			if tt.expectGetOTP {
				mockRedisRepo.AssertExpectations(t)
			}
		})
	}
}

// TestRequestOTP_EdgeCases tests edge cases and boundary conditions
func TestRequestOTP_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		purpose        string
		email          string
		emailError     error
		redisError     error
		emailSendError error
		expectedSuccess bool
		expectedError  string
		expectSetOTP   bool
		expectGetEmail bool
		expectSendMail bool
	}{
		{
			name:           "EmptyUserID",
			userID:         "",
			purpose:        "signup",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
		{
			name:           "EmptyPurpose",
			userID:         "user123",
			purpose:        "",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
		{
			name:           "VeryLongUserID",
			userID:         "very-long-user-id-that-exceeds-normal-limits-and-might-cause-issues-in-some-systems",
			purpose:        "signup",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
		{
			name:           "SpecialCharactersInUserID",
			userID:         "user-123_test@domain",
			purpose:        "signup",
			email:          "test@example.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
		{
			name:           "VeryLongEmail",
			userID:         "user123",
			purpose:        "signup",
			email:          "verylongemailaddressthatexceedsnormallimitsandmightcauseissuesinsomesystems@verylongdomainname.com",
			emailError:     nil,
			redisError:     nil,
			emailSendError: nil,
			expectedSuccess: true,
			expectedError:  "",
			expectSetOTP:   true,
			expectGetEmail: true,
			expectSendMail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepo)
			mockRedisRepo := new(MockRedisRepo)
			mockPhoenixService := new(MockPhoenixService)

			service := New(mockUserRepo, mockRedisRepo, mockPhoenixService)
			ctx := context.Background()

			// Setup mocks based on expectations
			if tt.expectSetOTP {
				mockRedisRepo.On("SetOTP", ctx, tt.userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration"), tt.purpose).Return(tt.redisError)
			}

			if tt.expectGetEmail {
				mockUserRepo.On("GetUserEmailById", ctx, tt.userID).Return(tt.email, tt.emailError)
			}

			if tt.expectSendMail {
				mockPhoenixService.On("SendMail", ctx, tt.userID, mock.AnythingOfType("phoenix.EmailTemplate")).Return(tt.emailSendError)
			}

			// Execute
			success, err := service.RequestOTP(ctx, tt.userID, tt.purpose)

			// Assertions
			assert.Equal(t, tt.expectedSuccess, success)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			if tt.expectSetOTP {
				mockRedisRepo.AssertExpectations(t)
			}
			if tt.expectGetEmail {
				mockUserRepo.AssertExpectations(t)
			}
			if tt.expectSendMail {
				mockPhoenixService.AssertExpectations(t)
			}
		})
	}
}

// TestVerifyOTP_EdgeCases tests edge cases and boundary conditions
func TestVerifyOTP_EdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		userID          string
		code            string
		purpose         string
		storedOTP       string
		redisGetError   error
		expectedSuccess bool
		expectedError   string
		expectGetOTP    bool
		expectDeleteOTP bool
	}{
		{
			name:            "EmptyUserID",
			userID:          "",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: true,
			expectedError:   "",
			expectGetOTP:    true,
			expectDeleteOTP: true,
		},
		{
			name:            "EmptyPurpose",
			userID:          "user123",
			code:            "123456",
			purpose:         "",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: true,
			expectedError:   "",
			expectGetOTP:    true,
			expectDeleteOTP: true,
		},
		{
			name:            "VeryLongCode",
			userID:          "user123",
			code:            "1234567890123456789012345678901234567890", // Very long code
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "invalid otp",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "SpecialCharactersInCode",
			userID:          "user123",
			code:            "123@456",
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "invalid otp",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "UnicodeCharactersInCode",
			userID:          "user123",
			code:            "123测试456",
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: false,
			expectedError:   "invalid otp",
			expectGetOTP:    true,
			expectDeleteOTP: false,
		},
		{
			name:            "NumericStringCode",
			userID:          "user123",
			code:            "123456",
			purpose:         "signup",
			storedOTP:       "123456",
			redisGetError:   nil,
			expectedSuccess: true,
			expectedError:   "",
			expectGetOTP:    true,
			expectDeleteOTP: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepo)
			mockRedisRepo := new(MockRedisRepo)
			mockPhoenixService := new(MockPhoenixService)

			service := New(mockUserRepo, mockRedisRepo, mockPhoenixService)
			ctx := context.Background()

			// Setup mocks based on expectations
			if tt.expectGetOTP {
				mockRedisRepo.On("GetOTP", ctx, tt.userID, tt.purpose).Return(tt.storedOTP, tt.redisGetError)
			}

			if tt.expectDeleteOTP {
				mockRedisRepo.On("DeleteOTP", ctx, tt.userID, tt.purpose).Return(nil)
			}


			// Execute
			success, err := service.VerifyOTP(ctx, tt.userID, tt.code, tt.purpose)

			// Assertions
			assert.Equal(t, tt.expectedSuccess, success)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			// Verify mock expectations
			if tt.expectGetOTP {
				mockRedisRepo.AssertExpectations(t)
			}
		})
	}
}
