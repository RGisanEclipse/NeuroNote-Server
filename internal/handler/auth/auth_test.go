package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	authhandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock service that satisfies authservice.Service
type mockAuthService struct{ mock.Mock }

// Helper function to create an empty error code for success cases
func noError() *appError.Code {
	return nil
}

func (m *mockAuthService) Signup(ctx context.Context, email, pw string) (authmodel.ServiceResponse, *appError.Code) {
	args := m.Called(ctx, email, pw)
	return args.Get(0).(authmodel.ServiceResponse), args.Get(1).(*appError.Code)
}
func (m *mockAuthService) Signin(ctx context.Context, email, pw string) (authmodel.ServiceResponse, *appError.Code) {
	args := m.Called(ctx, email, pw)
	return args.Get(0).(authmodel.ServiceResponse), args.Get(1).(*appError.Code)
}

func (m *mockAuthService) RefreshToken(ctx context.Context, refreshToken string) (authmodel.RefreshTokenServiceResponse, *appError.Code) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(authmodel.RefreshTokenServiceResponse), args.Get(1).(*appError.Code)
}

func (m *mockAuthService) SignupOTP(ctx context.Context, userId string) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, userId)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *mockAuthService) SignupOTPVerify(ctx context.Context, userId, code string) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, userId, code)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *mockAuthService) ForgotPasswordOTP(ctx context.Context, email string) (authmodel.GenericOTPResponse, *appError.Code) {
	args := m.Called(ctx, email)
	return args.Get(0).(authmodel.GenericOTPResponse), args.Get(1).(*appError.Code)
}

func (m *mockAuthService) ForgotPasswordOTPVerify(ctx context.Context, userId, code string) (authmodel.ForgotPasswordResponse, *appError.Code) {
	args := m.Called(ctx, userId, code)
	return args.Get(0).(authmodel.ForgotPasswordResponse), args.Get(1).(*appError.Code)
}

func (m *mockAuthService) ResetPassword(ctx context.Context, userId, password string) (authmodel.ResetPasswordResponse, *appError.Code) {
	args := m.Called(ctx, userId, password)
	return args.Get(0).(authmodel.ResetPasswordResponse), args.Get(1).(*appError.Code)
}

// Signup handler tests

func TestSignupHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.Request
		mockReturn     *authmodel.ServiceResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.Response
		expectCall     bool
	}{
		{
			name:    "Success",
			request: authmodel.Request{Email: "test@example.com", Password: "validPass@1234"},
			mockReturn: &authmodel.ServiceResponse{
				Success:     true,
				Message:     "Account created succesfully",
				AccessToken: "random-jwt-token",
				IsVerified:  false,
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.Response{
				Success:     true,
				Message:     "Account created succesfully",
				AccessToken: "random-jwt-token",
				IsVerified:  false,
			},
			expectCall: true,
		},
		{
			name: "EmailExists",
			request: authmodel.Request{
				Email:    "exists@example.com",
				Password: "validPass@1234",
			},
			mockReturn: &authmodel.ServiceResponse{
				Success: false,
				Message: appError.AuthEmailExists.Message,
			},
			mockError:      appError.AuthEmailExists,
			expectedStatus: http.StatusConflict,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.AuthEmailExists.Message,
			},
			expectCall: true,
		},
		{
			name:           "MissingEmail",
			request:        authmodel.Request{Password: "123456"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.EmailRequired.Message,
			},
			expectCall: false,
		},
		{
			name:           "MissingPassword",
			request:        authmodel.Request{Email: "user@example.com"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordRequired.Message,
			},
			expectCall: false,
		},
		{
			name:           "InvalidEmailFormat",
			request:        authmodel.Request{Email: "invalidemail.com", Password: "ValidPass@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.EmailInvalid.Message,
			},
			expectCall: false,
		},
		{
			name:           "ShortPassword",
			request:        authmodel.Request{Email: "a@b.com", Password: "123456"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordTooShort.Message,
			},
			expectCall: false,
		},
		{
			name:           "LongPassword",
			request:        authmodel.Request{Email: "a@b.com", Password: "VeryLongPasswordWithAllComponents@12345678999999999999"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordTooLong.Message,
			},
			expectCall: false,
		},
		{
			name:           "PasswordWithoutUppercase",
			request:        authmodel.Request{Email: "a@b.com", Password: "lowercase@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordMissingUppercase.Message,
			},
			expectCall: false,
		},
		{
			name:           "PasswordWithoutLowercase",
			request:        authmodel.Request{Email: "a@b.com", Password: "UPPERCASE@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordMissingLowercase.Message,
			},
			expectCall: false,
		},
		{
			name:           "PasswordWithoutDigit",
			request:        authmodel.Request{Email: "a@b.com", Password: "Password@"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordMissingDigit.Message,
			},
			expectCall: false,
		},
		{
			name:           "PasswordWithoutSpecialChar",
			request:        authmodel.Request{Email: "a@b.com", Password: "Password123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordMissingSpecialChar.Message,
			},
			expectCall: false,
		},
		{
			name:           "PasswordWithWhitespace",
			request:        authmodel.Request{Email: "a@b.com", Password: "Valid Pass@123"},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.PasswordContainsWhitespace.Message,
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

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					assert.Equal(t, tt.expectedBody.Message, resp["message"])
				}
				if tt.expectedBody.AccessToken != "" {
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.AccessToken, data["token"])
					assert.Equal(t, tt.expectedBody.IsVerified, data["isVerified"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				errorData := resp["error"].(map[string]interface{})
				assert.Equal(t, tt.expectedBody.Message, errorData["message"])
			}

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
		request        authmodel.Request
		mockReturn     *authmodel.ServiceResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.Response
		expectCall     bool
	}{
		{
			name:    "Success",
			request: authmodel.Request{Email: "user@example.com", Password: "123456"},
			mockReturn: &authmodel.ServiceResponse{
				Success:     true,
				Message:     "Logged in successfully",
				AccessToken: "valid-jwt-token",
				IsVerified:  false,
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.Response{
				Success:     true,
				Message:     "Logged in successfully",
				AccessToken: "valid-jwt-token",
				IsVerified:  false,
			},
			expectCall: true,
		},
		{
			name:    "WrongPassword",
			request: authmodel.Request{Email: "user@example.com", Password: "wrong"},
			mockReturn: &authmodel.ServiceResponse{
				Success: false,
				Message: appError.AuthIncorrectPassword.Message,
			},
			mockError:      appError.AuthIncorrectPassword,
			expectedStatus: http.StatusUnauthorized,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.AuthIncorrectPassword.Message,
			},
			expectCall: true,
		},
		{
			name:    "EmailDoesNotExist",
			request: authmodel.Request{Email: "ghost@example.com", Password: "123456"},
			mockReturn: &authmodel.ServiceResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
			},
			mockError:      appError.AuthEmailDoesntExist,
			expectedStatus: http.StatusNotFound,
			expectedBody: &authmodel.Response{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
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

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					assert.Equal(t, tt.expectedBody.Message, resp["message"])
				}
				if tt.expectedBody.AccessToken != "" {
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.AccessToken, data["token"])
					assert.Equal(t, tt.expectedBody.IsVerified, data["isVerified"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				errorData := resp["error"].(map[string]interface{})
				assert.Equal(t, tt.expectedBody.Message, errorData["message"])
			}

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
		mockReturn     *authmodel.GenericOTPResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.GenericOTPResponse
		expectCall     bool
	}{
		{
			name: "Success",
			request: authmodel.SignupOTPRequest{
				UserId: "user123",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
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
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "ServiceError",
			request: authmodel.SignupOTPRequest{
				UserId: "user123",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectCall: true,
		},
		{
			name:           "InvalidRequestBody",
			request:        authmodel.SignupOTPRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
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

		// Parse the new response format
		var resp map[string]interface{}
		_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					// The message should be in the data field for OTP handlers
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, data["errorMessage"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				errorData := resp["error"].(map[string]interface{})
				assert.Equal(t, tt.expectedBody.Message, errorData["message"])
			}

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
		request        authmodel.OTPVerifyRequest
		mockReturn     *authmodel.GenericOTPResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.GenericOTPResponse
		expectCall     bool
	}{
		{
			name: "Success_WithUserVerification",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			expectCall: true,
		},
		{
			name: "InvalidOTP_NoUserVerification",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "wrong123",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.OtpInvalid.Message,
			},
			mockError:      appError.OtpInvalid,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.OtpInvalid.Message,
			},
			expectCall: true,
		},
		{
			name: "OTPExpiredOrNotFound_NoUserVerification",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.OtpExpiredOrNotFound.Message,
			},
			mockError:      appError.OtpExpiredOrNotFound,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.OtpExpiredOrNotFound.Message,
			},
			expectCall: true,
		},
		{
			name: "OTPVerificationFailure_NoUserVerification",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: "OTP verification failed",
			},
			mockError:      noError(), // OTP service returns success=false but no error
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true, // Handler treats this as success since no error code
				Message: "OTP verification failed",
			},
			expectCall: true,
		},
		{
			name: "UserVerificationDatabaseError",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: "Failed to mark user as verified",
			},
			mockError:      noError(), // OTP verification succeeds but user verification fails
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true, // Handler treats this as success since no error code
				Message: "Failed to mark user as verified",
			},
			expectCall: true,
		},
		{
			name: "EmptyUserId",
			request: authmodel.OTPVerifyRequest{
				UserId: "",
				Code:   "123456",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "EmptyCode",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "EmptyUserIdAndCode",
			request: authmodel.OTPVerifyRequest{
				UserId: "",
				Code:   "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name:           "InvalidRequestBody",
			request:        authmodel.OTPVerifyRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "InternalServerError_OTPService",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectCall: true,
		},
		{
			name: "VeryLongUserId",
			request: authmodel.OTPVerifyRequest{
				UserId: "very-long-user-id-that-exceeds-normal-limits-and-might-cause-issues-in-some-systems",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			expectCall: true,
		},
		{
			name: "VeryLongCode",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "1234567890123456789012345678901234567890",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: "OTP verification failed",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true, // Handler treats this as success since no error code
				Message: "OTP verification failed",
			},
			expectCall: true,
		},
		{
			name: "SpecialCharactersInUserId",
			request: authmodel.OTPVerifyRequest{
				UserId: "user-123_test@domain",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			expectCall: true,
		},
		{
			name: "SpecialCharactersInCode",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123@456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: "OTP verification failed",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true, // Handler treats this as success since no error code
				Message: "OTP verification failed",
			},
			expectCall: true,
		},
		{
			name: "WhitespaceInUserId",
			request: authmodel.OTPVerifyRequest{
				UserId: " user123 ",
				Code:   "123456",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP verified successfully",
			},
			expectCall: true,
		},
		{
			name: "WhitespaceInCode",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   " 123456 ",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: "OTP verification failed",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true, // Handler treats this as success since no error code
				Message: "OTP verification failed",
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

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					// The message should be in the data field for OTP handlers
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, data["errorMessage"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				if resp["error"] != nil {
					errorData := resp["error"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, errorData["message"])
				} else {
					// For cases where there's no error but success=false, check the data field
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, data["errorMessage"])
				}
			}

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
			mockError:      noError(),
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
			mockReturn:     &authmodel.RefreshTokenServiceResponse{},
			mockError:      appError.AuthInvalidRefreshToken,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   &authmodel.RefreshTokenResponse{},
			expectCall:     true,
		},
		{
			name: "RefreshTokenMismatch",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "mismatched-token",
			},
			mockReturn:     &authmodel.RefreshTokenServiceResponse{},
			mockError:      appError.AuthRefreshTokenMismatch,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   &authmodel.RefreshTokenResponse{},
			expectCall:     true,
		},
		{
			name: "EmptyRefreshToken",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   &authmodel.RefreshTokenResponse{},
			expectCall:     false,
		},
		{
			name:           "InvalidRequestBody",
			request:        authmodel.RefreshTokenRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   &authmodel.RefreshTokenResponse{},
			expectCall:     false,
		},
		{
			name: "InternalServerError",
			request: authmodel.RefreshTokenRequest{
				RefreshToken: "valid-token",
			},
			mockReturn:     &authmodel.RefreshTokenServiceResponse{},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   &authmodel.RefreshTokenResponse{},
			expectCall:     true,
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

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectCall && tt.mockError.Error() == "" {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if resp["data"] != nil {
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.AccessToken, data["accessToken"])
				}
			} else if tt.mockError != nil && tt.mockError.Error() != "" {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				if resp["error"] != nil {
					errorData := resp["error"].(map[string]interface{})
					assert.NotEmpty(t, errorData["message"])
				}
			}

			if tt.expectCall {
				mockSvc.AssertExpectations(t)
			} else {
				mockSvc.AssertNotCalled(t, "RefreshToken")
			}
		})
	}
}

// ForgotPasswordOTP handler tests
func TestForgotPasswordOTPHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.ForgotPasswordOTPRequest
		mockReturn     *authmodel.GenericOTPResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.GenericOTPResponse
		expectCall     bool
	}{
		{
			name: "ValidRequest",
			request: authmodel.ForgotPasswordOTPRequest{
				Email: "test@example.com",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true,
				Message: "OTP sent successfully",
			},
			expectCall: true,
		},
		{
			name: "EmailDoesNotExist",
			request: authmodel.ForgotPasswordOTPRequest{
				Email: "nonexistent@example.com",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
			},
			mockError:      appError.AuthEmailDoesntExist,
			expectedStatus: http.StatusNotFound,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
			},
			expectCall: true,
		},
		{
			name: "EmptyEmail",
			request: authmodel.ForgotPasswordOTPRequest{
				Email: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name:           "InvalidRequestBody",
			request:        authmodel.ForgotPasswordOTPRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "OTPSendFailure",
			request: authmodel.ForgotPasswordOTPRequest{
				Email: "test@example.com",
			},
			mockReturn: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.AuthOtpSendFailure.Message,
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: true, // Handler treats this as success since no error code
				Message: appError.AuthOtpSendFailure.Message,
			},
			expectCall: true,
		},
		{
			name: "InternalServiceError",
			request: authmodel.ForgotPasswordOTPRequest{
				Email: "test@example.com",
			},
			mockReturn:     &authmodel.GenericOTPResponse{},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.GenericOTPResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("ForgotPasswordOTP", mock.Anything, tt.request.Email).
					Return(*tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/password/otp", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					// The message should be in the data field for OTP handlers
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, data["errorMessage"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				errorData := resp["error"].(map[string]interface{})
				assert.Equal(t, tt.expectedBody.Message, errorData["message"])
			}

			mockSvc.AssertExpectations(t)
		})
	}
}

// ForgotPasswordOTPVerify handler tests
func TestForgotPasswordOTPVerifyHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.OTPVerifyRequest
		mockReturn     *authmodel.ForgotPasswordResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.ForgotPasswordResponse
		expectCall     bool
	}{
		{
			name: "ValidRequest",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.ForgotPasswordResponse{
				Success: true,
				Message: "OTP verified successfully",
				UserId:  "user123",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: true,
				Message: "OTP verified successfully",
				UserId:  "user123",
			},
			expectCall: true,
		},
		{
			name: "InvalidOTP",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "wrong123",
			},
			mockReturn: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.OtpInvalid.Message,
			},
			mockError:      appError.OtpInvalid,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.OtpInvalid.Message,
			},
			expectCall: true,
		},
		{
			name: "OTPExpiredOrNotFound",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.OtpExpiredOrNotFound.Message,
			},
			mockError:      appError.OtpExpiredOrNotFound,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.OtpExpiredOrNotFound.Message,
			},
			expectCall: true,
		},
		{
			name: "EmptyUserId",
			request: authmodel.OTPVerifyRequest{
				UserId: "",
				Code:   "123456",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "EmptyCode",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name:           "InvalidRequestBody",
			request:        authmodel.OTPVerifyRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.ServerBadRequest.Message,
			},
			expectCall: false,
		},
		{
			name: "InternalServerError",
			request: authmodel.OTPVerifyRequest{
				UserId: "user123",
				Code:   "123456",
			},
			mockReturn:     &authmodel.ForgotPasswordResponse{},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.ForgotPasswordResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("ForgotPasswordOTPVerify", mock.Anything, tt.request.UserId, tt.request.Code).
					Return(*tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/password/otp/verify", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					// The message should be in the data field for OTP handlers
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, data["errorMessage"])
				}
				if tt.expectedBody.UserId != "" {
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.UserId, data["userId"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				errorData := resp["error"].(map[string]interface{})
				assert.Equal(t, tt.expectedBody.Message, errorData["message"])
			}

			mockSvc.AssertExpectations(t)
		})
	}
}

// PasswordReset handler tests
func TestPasswordResetHandler(t *testing.T) {
	tests := []struct {
		name           string
		request        authmodel.ResetPasswordRequest
		mockReturn     *authmodel.ResetPasswordResponse
		mockError      error
		expectedStatus int
		expectedBody   *authmodel.ResetPasswordResponse
		expectCall     bool
	}{
		{
			name: "ValidRequest",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "newpassword123",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: true,
				Message: "Password Reset successfully",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: true,
				Message: "Password Reset successfully",
			},
			expectCall: true,
		},
		{
			name: "PasswordResetFailure",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "newpassword123",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: "Failed to reset password",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: true, // Handler returns success: true for HTTP 200 responses
				Message: "Failed to reset password",
			},
			expectCall: true,
		},
		{
			name: "EmptyUserId",
			request: authmodel.ResetPasswordRequest{
				UserId:   "",
				Password: "newpassword123",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: "Invalid userId",
			},
			mockError:      appError.ServerBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: "bad request",
			},
			expectCall: false,
		},
		{
			name: "EmptyPassword",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: "Failed to reset password",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: true, // Handler returns success: true for HTTP 200 responses
				Message: "Failed to reset password",
			},
			expectCall: true,
		},
		{
			name: "WeakPassword",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "weak",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: "Password doesn't match the required criteria",
			},
			mockError:      noError(),
			expectedStatus: http.StatusOK,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: true, // Handler returns success: true for HTTP 200 responses
				Message: "Password doesn't match the required criteria",
			},
			expectCall: true,
		},
		{
			name:           "InvalidRequestBody",
			request:        authmodel.ResetPasswordRequest{},
			mockError:      appError.ServerBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: "bad request",
			},
			expectCall: false,
		},
		{
			name: "OTPNotVerified",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "newpassword123",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.AuthPasswordOtpNotVerified.Message,
			},
			mockError:      appError.AuthPasswordOtpNotVerified,
			expectedStatus: http.StatusBadRequest,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.AuthPasswordOtpNotVerified.Message,
			},
			expectCall: true,
		},
		{
			name: "RedisFlagCheckFailed",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "newpassword123",
			},
			mockReturn: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectCall: true,
		},
		{
			name: "InternalServerError",
			request: authmodel.ResetPasswordRequest{
				UserId:   "user1234567890",
				Password: "newpassword123",
			},
			mockReturn:     &authmodel.ResetPasswordResponse{},
			mockError:      appError.ServerInternalError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody: &authmodel.ResetPasswordResponse{
				Success: false,
				Message: appError.ServerInternalError.Message,
			},
			expectCall:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mockAuthService)
			if tt.expectCall {
				mockSvc.On("ResetPassword", mock.Anything, tt.request.UserId, tt.request.Password).
					Return(*tt.mockReturn, tt.mockError).Once()
			}

			r := mux.NewRouter()
			authhandler.RegisterAuthRoutes(r, mockSvc)

			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/password/reset", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Parse the new response format
			var resp map[string]interface{}
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if tt.expectedBody.Success {
				// For success cases, check the data field
				assert.True(t, resp["success"].(bool))
				if tt.expectedBody.Message != "" {
					// The message should be in the data field for password reset handler
					data := resp["data"].(map[string]interface{})
					assert.Equal(t, tt.expectedBody.Message, data["errorMessage"])
				}
			} else {
				// For error cases, check the error field
				assert.False(t, resp["success"].(bool))
				errorData := resp["error"].(map[string]interface{})
				assert.Equal(t, tt.expectedBody.Message, errorData["message"])
			}

			mockSvc.AssertExpectations(t)
		})
	}
}
