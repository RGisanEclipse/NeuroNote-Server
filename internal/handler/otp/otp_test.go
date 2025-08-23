package otp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	models "github.com/RGisanEclipse/NeuroNote-Server/internal/models/otp"
)

type MockOTPService struct {
	mock.Mock
}

func (m *MockOTPService) RequestOTP(ctx context.Context, userId string, purpose string) (*models.OTPResponse, error) {
	args := m.Called(ctx, userId, purpose)
	return args.Get(0).(*models.OTPResponse), args.Error(1)
}

func (m *MockOTPService) VerifyOTP(ctx context.Context, userID string, code string, purpose string) (*models.OTPResponse, error) {
	args := m.Called(ctx, userID, code, purpose)
	return args.Get(0).(*models.OTPResponse), args.Error(1)
}

func TestRequestOTPHandler(t *testing.T) {
	mockService := new(MockOTPService)
	handler := requestOTPHandler(mockService)

	tests := []struct {
		name           string
		userId         string
		requestBody    interface{}
		serviceResponse *models.OTPResponse
		serviceError   error
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:           "Success",
			userId:         "test-user-id",
			requestBody:    models.OTPRequest{Purpose: "signup"},
			serviceResponse: &models.OTPResponse{Success: true, Message: "OTP sent successfully"},
			serviceError:   nil,
			expectedStatus: http.StatusOK,
			expectedBody:   &models.OTPResponse{Success: true, Message: "OTP sent successfully"},
		},
		{
			name:           "Unauthorized - Missing User ID",
			userId:         "",
			requestBody:    models.OTPRequest{Purpose: "signup"},
			serviceResponse: nil,
			serviceError:   nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "unauthorized access\n",
		},
		{
			name:           "Service Error",
			userId:         "test-user-id",
			requestBody:    models.OTPRequest{Purpose: "signup"},
			serviceResponse: &models.OTPResponse{Success: false, Message: "Internal Server Error"},
			serviceError:   errors.New("internal server error"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error\n",
		},
		{
			name:           "Invalid Request Body",
			userId:         "test-user-id",
			requestBody:    "invalid json",
			serviceResponse: nil,
			serviceError:   nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid request body\n",
		},
		{
			name:           "Invalid Purpose",
			userId:         "test-user-id",
			requestBody:    models.OTPRequest{Purpose: "invalid purpose"},
			serviceResponse: nil,
			serviceError:   nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid purpose\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody io.Reader
			if tt.requestBody != nil {
				if s, ok := tt.requestBody.(string); ok {
					reqBody = bytes.NewBufferString(s)
				} else {
					jsonBody, _ := json.Marshal(tt.requestBody)
					reqBody = bytes.NewBuffer(jsonBody)
				}
			}
			req, _ := http.NewRequest("POST", "/auth/otp/request", reqBody)
			if tt.userId != "" {
				ctx := context.WithValue(req.Context(), user.UserIdKey, tt.userId)
				req = req.WithContext(ctx)
			}
			rr := httptest.NewRecorder()

			if tt.userId != "" && tt.name != "Unauthorized - Missing User ID" && tt.name != "Invalid Request Body" && tt.name != "Invalid Purpose" {
				purpose := ""
				if reqModel, ok := tt.requestBody.(models.OTPRequest); ok {
					purpose = reqModel.Purpose
				}
				mockService.On("RequestOTP", mock.Anything, tt.userId, purpose).Return(tt.serviceResponse, tt.serviceError).Once()
			}

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			if tt.expectedStatus == http.StatusOK {
				var actualResp models.OTPResponse
				err := json.Unmarshal(rr.Body.Bytes(), &actualResp)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, &actualResp)
			} else {
				assert.Equal(t, tt.expectedBody, rr.Body.String())
			}

			if tt.userId != "" && tt.name != "Unauthorized - Missing User ID" && tt.name != "Invalid Request Body" && tt.name != "Invalid Purpose" {
				mockService.AssertExpectations(t)
			}
		})
	}
}

func TestVerifyOTPHandler(t *testing.T) {
	mockService := new(MockOTPService)
	handler := verifyOTPHandler(mockService)

	tests := []struct {
		name           string
		userId         string
		requestBody    interface{}
		serviceResponse *models.OTPResponse
		serviceError   error
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:           "Success",
			userId:         "test-user-id",
			requestBody:    models.OTPVerifyRequest{OTP: "123456", Purpose: "signup"},
			serviceResponse: &models.OTPResponse{Success: true, Message: "OTP verified successfully"},
			serviceError:   nil,
			expectedStatus: http.StatusOK,
			expectedBody:   &models.OTPResponse{Success: true, Message: "OTP verified successfully"},
		},
		{
			name:           "Unauthorized - Missing User ID",
			userId:         "",
			requestBody:    models.OTPVerifyRequest{OTP: "123456", Purpose: "signup"},
			serviceResponse: nil,
			serviceError:   nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "unauthorized access\n",
		},
		{
			name:           "Invalid Request Body",
			userId:         "test-user-id",
			requestBody:    "invalid json",
			serviceResponse: nil,
			serviceError:   nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid request body\n",
		},
		{
			name:           "Missing OTP Code",
			userId:         "test-user-id",
			requestBody:    models.OTPVerifyRequest{OTP: ""},
			serviceResponse: nil,
			serviceError:   nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "code is required\n",
		},
		{
			name:           "Service Error - Invalid OTP",
			userId:         "test-user-id",
			requestBody:    models.OTPVerifyRequest{OTP: "654321", Purpose: "signup"},
			serviceResponse: &models.OTPResponse{Success: false, Message: "Invalid OTP"},
			serviceError:   errors.New("Invalid OTP"),
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid OTP\n",
		},
		{
			name:           "Service Error - Internal",
			userId:         "test-user-id",
			requestBody:    models.OTPVerifyRequest{OTP: "123456", Purpose: "signup"},
			serviceResponse: &models.OTPResponse{Success: false, Message: "Internal Server Error"},
			serviceError:   errors.New("internal server error"),
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "internal server error\n",
		},
		{
			name:           "Invalid Purpose",
			userId:         "test-user-id",
			requestBody:    models.OTPVerifyRequest{OTP: "123456", Purpose: "invalid purpose"},
			serviceResponse: &models.OTPResponse{Success: false, Message: "invalid purpose"},
			serviceError:   errors.New("invalid purpose"),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid purpose\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody io.Reader
			if tt.requestBody != nil {
				if s, ok := tt.requestBody.(string); ok {
					reqBody = bytes.NewBufferString(s)
				} else {
					jsonBody, _ := json.Marshal(tt.requestBody)
					reqBody = bytes.NewBuffer(jsonBody)
				}
			}

			req, _ := http.NewRequest("POST", "/auth/otp/verify", reqBody)
			if tt.userId != "" {
				ctx := context.WithValue(req.Context(), user.UserIdKey, tt.userId)
				req = req.WithContext(ctx)
			}
			rr := httptest.NewRecorder()

			if tt.userId != "" && tt.name != "Unauthorized - Missing User ID" && tt.name != "Invalid Request Body" && tt.name != "Missing OTP Code" && tt.name != "Invalid Purpose" {
				otpCode := ""
				purpose := ""
				if reqModel, ok := tt.requestBody.(models.OTPVerifyRequest); ok {
					otpCode = reqModel.OTP
					purpose = reqModel.Purpose
				}
				mockService.On("VerifyOTP", mock.Anything, tt.userId, otpCode, purpose).Return(tt.serviceResponse, tt.serviceError).Once()
			}

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			if tt.expectedStatus == http.StatusOK {
				var actualResp models.OTPResponse
				err := json.Unmarshal(rr.Body.Bytes(), &actualResp)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, &actualResp)
			} else {
				assert.Equal(t, tt.expectedBody, rr.Body.String())
			}

			if tt.userId != "" && tt.name != "Unauthorized - Missing User ID" && tt.name != "Invalid Request Body" && tt.name != "Missing OTP Code" && tt.name != "Invalid Purpose" {
				mockService.AssertExpectations(t)
			}
		})
	}
}