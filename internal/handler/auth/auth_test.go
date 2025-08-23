package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	authhandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

// Mock service that satisfies authservice.Service
type mockAuthService struct{ mock.Mock }

func (m *mockAuthService) Signup(ctx context.Context, email, pw string) (authmodel.AuthServiceResponse, error) {
	args := m.Called(ctx, email, pw)
	return args.Get(0).(authmodel.AuthServiceResponse), args.Error(1)
}
func (m *mockAuthService) Signin(ctx context.Context, email, pw string) (authmodel.AuthServiceResponse, error) {
	args := m.Called(ctx, email, pw)
	return args.Get(0).(authmodel.AuthServiceResponse), args.Error(1)
}

func (m *mockAuthService) RefreshToken(ctx context.Context, refreshToken string) (authmodel.RefreshTokenServiceResponse, error) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(authmodel.RefreshTokenServiceResponse), args.Error(1)
}

// Signup handler tests

func TestSignupHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.AuthRequest
		mockReturn     *authmodel.AuthServiceResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.AuthResponse
		expectCall     bool
	}{
		{
			name: "Success",
			request: authmodel.AuthRequest{Email: "test@example.com", Password: "validPass@1234"},
			mockReturn: &authmodel.AuthServiceResponse{
				Success: true,
				Message: "Account created succesfully",
				AccessToken: "random-jwt-token",
				IsVerified: false,
			},
			mockError: nil,
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.AuthResponse{
				Success: true,
				Message: "Account created succesfully",
				AccessToken: "random-jwt-token",
				IsVerified: false,
			},
			expectCall: true,
		},
		{
			name: "EmailExists",
			request: authmodel.AuthRequest{Email: "exists@example.com", Password: "validPass@1234"},
			mockReturn: &authmodel.AuthServiceResponse{
				Success: false,
				Message: authErr.AuthError.EmailExists,
			},
			mockError: errors.New(authErr.AuthError.EmailExists),
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.EmailExists,
			},
			expectCall: true,
		},
		{
			name: "MissingEmail",
			request: authmodel.AuthRequest{Password: "123456"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.EmailRequired,
			},
			expectCall: false,
		},
		{
			name: "MissingPassword",
			request: authmodel.AuthRequest{Email: "user@example.com"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordRequired,
			},
			expectCall: false,
		},
		{
			name: "InvalidEmailFormat",
			request: authmodel.AuthRequest{Email: "invalidemail.com", Password: "ValidPass@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.InvalidEmail,
			},
			expectCall: false,
		},
		{
			name: "ShortPassword",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "123456"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordTooShort,
			},
			expectCall: false,
		},
		{
			name: "LongPassword",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "VeryLongPasswordWithAllComponents@12345678999999999999"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordTooLong,
			},
			expectCall: false,
		},
		{
			name: "PasswordWithoutUppercase",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "lowercase@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordMissingUppercase,
			},
			expectCall: false,
		},
		{
			name: "PasswordWithoutLowercase",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "UPPERCASE@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordMissingLowercase,
			},
			expectCall: false,
		},
		{
			name: "PasswordWithoutDigit",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "Password@"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordMissingDigit,
			},
			expectCall: false,
		},
		{
			name: "PasswordWithoutSpecialChar",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "Password123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordMissingSpecialCharacter,
			},
			expectCall: false,
		},
		{
			name: "PasswordWithWhitespace",
			request: authmodel.AuthRequest{Email: "a@b.com", Password: "Valid Pass@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.PasswordContainsWhitespace,
			},
			expectCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("Signup", mock.Anything, tt.request.Email, tt.request.Password).
					Return(*tt.mockReturn, tt.mockError).Once()
			}
			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var resp authmodel.AuthResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			assert.Equal(t, tt.expectedBody.Success, resp.Success)
			assert.Equal(t, tt.expectedBody.Message, resp.Message)
			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "Signup")
			}
		})
	}
}

// Signin handler tests


func TestSigninHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.AuthRequest
		mockReturn     *authmodel.AuthServiceResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.AuthResponse
		expectCall     bool
	}{
		{
			name: "Success",
			request: authmodel.AuthRequest{Email: "user@example.com", Password: "123456"},
			mockReturn: &authmodel.AuthServiceResponse{
				Success: true,
				Message: "Logged in successfully",
				AccessToken: "valid-jwt-token",
				IsVerified: false,
			},
			mockError: nil,
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.AuthResponse{
				Success: true,
				Message: "Logged in successfully",
				AccessToken: "valid-jwt-token",
				IsVerified: false,
			},
			expectCall: true,
		},
		{
			name: "WrongPassword",
			request: authmodel.AuthRequest{Email: "user@example.com", Password: "wrong"},
			mockReturn: &authmodel.AuthServiceResponse{
				Success: false,
				Message: authErr.AuthError.IncorrectPassword,
			},
			mockError: errors.New(authErr.AuthError.IncorrectPassword),
			expectedStatus: http.StatusUnauthorized,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.IncorrectPassword,
			},
			expectCall: true,
		},
		{
			name: "EmailDoesNotExist",
			request: authmodel.AuthRequest{Email: "ghost@example.com", Password: "123456"},
			mockReturn: &authmodel.AuthServiceResponse{
				Success: false,
				Message: authErr.AuthError.EmailDoesntExist,
			},
			mockError: errors.New(authErr.AuthError.EmailDoesntExist),
			expectedStatus: http.StatusUnauthorized,
			expectedBody: &authmodel.AuthResponse{
				Success: false,
				Message: authErr.AuthError.EmailDoesntExist,
			},
			expectCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("Signin", mock.Anything, tt.request.Email, tt.request.Password).
					Return(*tt.mockReturn, tt.mockError).Once()
			}
			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/signin", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var resp authmodel.AuthResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			assert.Equal(t, tt.expectedBody.Success, resp.Success)
			assert.Equal(t, tt.expectedBody.Message, resp.Message)
			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "Signin")
			}
		})
	}
}