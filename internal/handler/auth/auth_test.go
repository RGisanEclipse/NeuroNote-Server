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
	otpErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/otp"
	serverErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
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

func (m *mockAuthService) SignupOTP(ctx context.Context, userId string) (authmodel.SignupOTPResponse, error) {
	args := m.Called(ctx, userId)
	return args.Get(0).(authmodel.SignupOTPResponse), args.Error(1)
}

func (m *mockAuthService) SignupOTPVerify(ctx context.Context, userId, code string) (authmodel.SignupOTPResponse, error) {
	args := m.Called(ctx, userId, code)
	return args.Get(0).(authmodel.SignupOTPResponse), args.Error(1)
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
			req := httptest.NewRequest("POST", "/api/v1/auth/signup", bytes.NewReader(body))
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
			req := httptest.NewRequest("POST", "/api/v1/auth/signin", bytes.NewReader(body))
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

// SignupOTP handler tests
func TestSignupOTPHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.SignupOTPRequest
		mockReturn     *authmodel.SignupOTPResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.SignupOTPResponse
		expectCall     bool
	}{
		{
			name: "Success",
			request: authmodel.SignupOTPRequest{
				UserId: "user123",
			},
			mockReturn: &authmodel.SignupOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			expectCall: true,
		},
		{
			name: "EmptyUserId",
			request: authmodel.SignupOTPRequest{
				UserId: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.BadRequest,
			},
			expectCall: false,
		},
		{
			name: "ServiceError",
			request: authmodel.SignupOTPRequest{
				UserId: "user123",
			},
			mockReturn: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.InternalError,
			},
			mockError:      errors.New(serverErr.ServerError.InternalError),
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.InternalError,
			},
			expectCall: true,
		},
		{
			name: "InvalidRequestBody",
			request: authmodel.SignupOTPRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.BadRequest,
			},
			expectCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("SignupOTP", mock.Anything, tt.request.UserId).
					Return(*tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/signup/otp", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var resp authmodel.SignupOTPResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			assert.Equal(t, tt.expectedBody.Success, resp.Success)
			assert.Equal(t, tt.expectedBody.Message, resp.Message)

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "SignupOTP")
			}
		})
	}
}

// SignupOTPVerify handler tests
func TestSignupOTPVerifyHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.SignupOTPVerifyRequest
		mockReturn     *authmodel.SignupOTPResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.SignupOTPResponse
		expectCall     bool
	}{
		{
			name: "Success",
			request: authmodel.SignupOTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.SignupOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			expectCall: true,
		},
		{
			name: "InvalidOTP",
			request: authmodel.SignupOTPVerifyRequest{
				UserId: "user123",
				Code:   "wrong123",
			},
			mockReturn: &authmodel.SignupOTPResponse{
				Success: false,
				Message: otpErr.OTPError.InvalidOTP,
			},
			mockError:      errors.New(otpErr.OTPError.InvalidOTP),
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: otpErr.OTPError.InvalidOTP,
			},
			expectCall: true,
		},
		{
			name: "OTPExpiredOrNotFound",
			request: authmodel.SignupOTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.SignupOTPResponse{
				Success: false,
				Message: otpErr.OTPError.OTPExpiredOrNotFound,
			},
			mockError:      errors.New(otpErr.OTPError.OTPExpiredOrNotFound),
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: otpErr.OTPError.OTPExpiredOrNotFound,
			},
			expectCall: true,
		},
		{
			name: "EmptyUserId",
			request: authmodel.SignupOTPVerifyRequest{
				UserId: "",
				Code:   "123456",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.BadRequest,
			},
			expectCall: false,
		},
		{
			name: "EmptyCode",
			request: authmodel.SignupOTPVerifyRequest{
				UserId: "user123",
				Code:   "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.BadRequest,
			},
			expectCall: false,
		},
		{
			name: "InvalidRequestBody",
			request: authmodel.SignupOTPVerifyRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.BadRequest,
			},
			expectCall: false,
		},
		{
			name: "InternalServerError",
			request: authmodel.SignupOTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.InternalError,
			},
			mockError:      errors.New(serverErr.ServerError.InternalError),
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.SignupOTPResponse{
				Success: false,
				Message: serverErr.ServerError.InternalError,
			},
			expectCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("SignupOTPVerify", mock.Anything, tt.request.UserId, tt.request.Code).
					Return(*tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/signup/otp/verify", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var resp authmodel.SignupOTPResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			assert.Equal(t, tt.expectedBody.Success, resp.Success)
			assert.Equal(t, tt.expectedBody.Message, resp.Message)

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "SignupOTPVerify")
			}
		})
	}
}

// RefreshToken handler tests
func TestRefreshTokenHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.RefreshTokenRequest
		mockReturn     *authmodel.RefreshTokenServiceResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.RefreshTokenResponse
		expectCall     bool
	}{
		{
			name: "Success",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "valid-refresh-token",
			},
			mockReturn: &authmodel.RefreshTokenServiceResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.RefreshTokenResponse{
				AccessToken: "new-access-token",
			},
			expectCall: true,
		},
		{
			name: "InvalidRefreshToken",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			mockReturn: &authmodel.RefreshTokenServiceResponse{},
			mockError:      errors.New(authErr.AuthError.InvalidRefreshToken),
			expectedStatus: http.StatusUnauthorized,
			expectedBody: &authmodel.RefreshTokenResponse{},
			expectCall: true,
		},
		{
			name: "RefreshTokenMismatch",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "mismatched-token",
			},
			mockReturn: &authmodel.RefreshTokenServiceResponse{},
			mockError:      errors.New(authErr.AuthError.RefreshTokenMismatch),
			expectedStatus: http.StatusUnauthorized,
			expectedBody: &authmodel.RefreshTokenResponse{},
			expectCall: true,
		},
		{
			name: "EmptyRefreshToken",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.RefreshTokenResponse{},
			expectCall: false,
		},
		{
			name: "InvalidRequestBody",
			request: authmodel.RefreshTokenRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.RefreshTokenResponse{},
			expectCall: false,
		},
		{
			name: "InternalServerError",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "valid-token",
			},
			mockReturn: &authmodel.RefreshTokenServiceResponse{},
			mockError:      errors.New(serverErr.ServerError.InternalError),
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.RefreshTokenResponse{},
			expectCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("RefreshToken", mock.Anything, tt.request.RefreshToken).
					Return(*tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/token/refresh", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			var resp authmodel.RefreshTokenResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			if tt.expectCall && tt.mockError == nil {
				assert.Equal(t, tt.expectedBody.AccessToken, resp.AccessToken)
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "RefreshToken")
			}
		})
	}
}