package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	authhandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// HTTP-specific handler tests

func TestSignupHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		contentType    string
		mockReturn     authmodel.ServiceResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"email":"test@example.com","password":"validPass@1234"}`,
			contentType: "application/json",
			mockReturn: authmodel.ServiceResponse{
				Success:     true,
				Message:     "Account created successfully",
				AccessToken: "random-jwt-token",
				IsVerified:  false,
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:        "ServiceError_ReturnsCorrectStatusCode",
			requestBody: `{"email":"exists@example.com","password":"validPass@1234"}`,
			contentType: "application/json",
			mockReturn: authmodel.ServiceResponse{
				Success: false,
				Message: appError.AuthEmailExists.Message,
			},
			mockError:      appError.AuthEmailExists,
			expectedStatus: http.StatusConflict,
			expectCall:     true,
		},
		{
			name:           "InvalidJSON_Returns400",
			requestBody:    `{"email":"test@example.com","password":}`,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:        "WrongContentType_StillProcessesJSON",
			requestBody: `{"email":"test@example.com","password":"validPass@1234"}`,
			contentType: "text/plain",
			mockReturn: authmodel.ServiceResponse{
				Success:     true,
				Message:     "Account created successfully",
				AccessToken: "random-jwt-token",
				IsVerified:  false,
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "EmptyBody_Returns400",
			requestBody:    ``,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("Signup", mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				Signup: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/signup", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", tt.contentType)
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "Signup")
			}
		})
	}
}

func TestSigninHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.ServiceResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"email":"user@example.com","password":"ValidPass123@"}`,
			mockReturn: authmodel.ServiceResponse{
				Success:     true,
				Message:     "Logged in successfully",
				AccessToken: "valid-jwt-token",
				IsVerified:  false,
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:        "Unauthorized_Returns401",
			requestBody: `{"email":"user@example.com","password":"wrongPassword1@"}`,
			mockReturn: authmodel.ServiceResponse{
				Success: false,
				Message: appError.AuthIncorrectPassword.Message,
			},
			mockError:      appError.AuthIncorrectPassword,
			expectedStatus: http.StatusUnauthorized,
			expectCall:     true,
		},
		{
			name:        "NotFound_Returns404",
			requestBody: `{"email":"ghost@example.com","password":"randomPassword!2"}`,
			mockReturn: authmodel.ServiceResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
			},
			mockError:      appError.AuthEmailDoesntExist,
			expectedStatus: http.StatusNotFound,
			expectCall:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("Signin", mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				Signin: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/signin", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "Signin")
			}
		})
	}
}

func TestRefreshTokenHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.RefreshTokenServiceResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"refresh_token":"valid-refresh-token"}`,
			mockReturn: authmodel.RefreshTokenServiceResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "Unauthorized_Returns401",
			requestBody:    `{"refresh_token":"invalid-token"}`,
			mockReturn:     authmodel.RefreshTokenServiceResponse{},
			mockError:      appError.AuthInvalidRefreshToken,
			expectedStatus: http.StatusUnauthorized,
			expectCall:     true,
		},
		{
			name:           "EmptyToken_Returns400",
			requestBody:    `{"refresh_token":""}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("RefreshToken", mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				Signin: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/token/refresh", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "RefreshToken")
			}
		})
	}
}

func TestSignupOTPHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.GenericOTPResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"userId":"user123"}`,
			mockReturn: authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "EmptyUserId_Returns400",
			requestBody:    `{"userId":""}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:           "InvalidJSON_Returns400",
			requestBody:    `{"userId":}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("SignupOTP", mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				Signup: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/signup/otp", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "SignupOTP")
			}
		})
	}
}

func TestSignupOTPVerifyHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.GenericOTPResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"userId":"user123","code":"123456"}`,
			mockReturn: authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "EmptyUserId_Returns400",
			requestBody:    `{"userId":"","code":"123456"}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:           "EmptyCode_Returns400",
			requestBody:    `{"userId":"user123","code":""}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("SignupOTPVerify", mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				Signup: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/signup/otp/verify", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "SignupOTPVerify")
			}
		})
	}
}

func TestForgotPasswordOTPHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.ForgotPasswordOTPResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"email":"test@example.com"}`,
			mockReturn: authmodel.ForgotPasswordOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
				UserId:  "user123",
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "EmptyEmail_Returns400",
			requestBody:    `{"email":""}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:        "NotFound_Returns404",
			requestBody: `{"email":"nonexistent@example.com"}`,
			mockReturn: authmodel.ForgotPasswordOTPResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
				UserId:  "",
			},
			mockError:      appError.AuthEmailDoesntExist,
			expectedStatus: http.StatusNotFound,
			expectCall:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("ForgotPasswordOTP", mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				ForgotPassword: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/password/otp", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "ForgotPasswordOTP")
			}
		})
	}
}

func TestForgotPasswordOTPVerifyHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.ForgotPasswordResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"userId":"user123","code":"123456"}`,
			mockReturn: authmodel.ForgotPasswordResponse{
				Success: true,
				Message: "OTP verified successfully",
				UserId:  "user123",
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "EmptyUserId_Returns400",
			requestBody:    `{"userId":"","code":"123456"}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:           "EmptyCode_Returns400",
			requestBody:    `{"userId":"user123","code":""}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("ForgotPasswordOTPVerify", mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				ForgotPassword: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/password/otp/verify", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "ForgotPasswordOTPVerify")
			}
		})
	}
}

func TestPasswordResetHandler_HTTPConcerns(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		mockReturn     authmodel.ResetPasswordResponse
		mockError      *appError.Code
		expectedStatus int
		expectCall     bool
	}{
		{
			name:        "Success_Returns200",
			requestBody: `{"userId":"user1234567890","password":"newpassword123"}`,
			mockReturn: authmodel.ResetPasswordResponse{
				Success: true,
				Message: "Password Reset successfully",
			},
			mockError:      mocks.NoError(),
			expectedStatus: http.StatusOK,
			expectCall:     true,
		},
		{
			name:           "EmptyUserId_Returns400",
			requestBody:    `{"userId":"","password":"newpassword123"}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:           "InvalidUserIdLength_Returns400",
			requestBody:    `{"userId":"short","password":"newpassword123"}`,
			expectedStatus: http.StatusBadRequest,
			expectCall:     false,
		},
		{
			name:        "OTPNotVerified_Returns400",
			requestBody: `{"userId":"user1234567890","password":"newpassword123"}`,
			mockReturn: authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.AuthPasswordOtpNotVerified.Message,
			},
			mockError:      appError.AuthPasswordOtpNotVerified,
			expectedStatus: http.StatusBadRequest,
			expectCall:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.MockAuthService)
			if tt.expectCall {
				mockSvc.On("ResetPassword", mock.Anything, mock.Anything, mock.Anything).
					Return(tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			svc := &authservice.Service{
				ForgotPassword: mockSvc,
			}
			authhandler.RegisterAuthRoutes(r, svc)

			req := httptest.NewRequest("POST", "/api/v1/auth/password/reset", bytes.NewReader([]byte(tt.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			assert.Contains(t, resp, "success")
			assert.Contains(t, resp, "status")
			assert.Contains(t, resp, "response")

			if tt.expectedStatus == http.StatusOK {
				assert.True(t, resp["success"].(bool))
			} else {
				assert.False(t, resp["success"].(bool))
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "ResetPassword")
			}
		})
	}
}

func TestAuthRoutes_Registration(t *testing.T) {
	// Test that all routes are properly registered
	mockSvc := new(mocks.MockAuthService)
	svc := &authservice.Service{
		Signup:         mockSvc,
		Signin:         mockSvc,
		ForgotPassword: mockSvc,
	}

	r := mux.NewRouter()
	authhandler.RegisterAuthRoutes(r, svc)

	// Test that routes exist by making requests to them
	testRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/auth/signup"},
		{"POST", "/api/v1/auth/signin"},
		{"POST", "/api/v1/auth/signup/otp"},
		{"POST", "/api/v1/auth/signup/otp/verify"},
		{"POST", "/api/v1/auth/token/refresh"},
		{"POST", "/api/v1/auth/password/otp"},
		{"POST", "/api/v1/auth/password/otp/verify"},
		{"POST", "/api/v1/auth/password/reset"},
	}

	for _, route := range testRoutes {
		t.Run("Route_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			// Should not get 404 (route not found)
			assert.NotEqual(t, http.StatusNotFound, rec.Code, "Route %s %s should be registered", route.method, route.path)
		})
	}
}
