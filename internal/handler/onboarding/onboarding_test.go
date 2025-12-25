package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOnboardUserHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func(*mocks.MockOnboardingService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "Success",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "User onboarded successfully",
				},
			},
		},
		{
			name:        "InvalidJSON",
			requestBody: "invalid json",
			mockSetup: func(svc *mocks.MockOnboardingService) {
				// No mocks needed for JSON parsing errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.ServerBadRequest.Status),
				"response": map[string]interface{}{
					"errorCode": appError.ServerBadRequest.Code,
					"message":   appError.ServerBadRequest.Message,
				},
			},
		},
		{
			name: "ValidationError_NameTooShort",
			requestBody: om.Request{
				Name:   "",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.OBNameTooShort)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.OBNameTooShort.Status),
				"response": map[string]interface{}{
					"errorCode": appError.OBNameTooShort.Code,
					"message":   appError.OBNameTooShort.Message,
				},
			},
		},
		{
			name: "ValidationError_NameTooLong",
			requestBody: om.Request{
				Name:   "ThisIsAVeryLongNameThatExceedsFiftyCharactersAndShouldFailValidation",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.OBNameTooLong)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.OBNameTooLong.Status),
				"response": map[string]interface{}{
					"errorCode": appError.OBNameTooLong.Code,
					"message":   appError.OBNameTooLong.Message,
				},
			},
		},
		{
			name: "ValidationError_InvalidAge",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    12,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.OBInvalidAge)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.OBInvalidAge.Status),
				"response": map[string]interface{}{
					"errorCode": appError.OBInvalidAge.Code,
					"message":   appError.OBInvalidAge.Message,
				},
			},
		},
		{
			name: "ValidationError_InvalidGender",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    25,
				Gender: 2,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.OBInvalidGender)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.OBInvalidGender.Status),
				"response": map[string]interface{}{
					"errorCode": appError.OBInvalidGender.Code,
					"message":   appError.OBInvalidGender.Message,
				},
			},
		},
		{
			name: "UserNotFound",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.AuthUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.AuthUserNotFound.Status),
				"response": map[string]interface{}{
					"errorCode": appError.AuthUserNotFound.Code,
					"message":   appError.AuthUserNotFound.Message,
				},
			},
		},
		{
			name: "UserAlreadyOnboarded",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.OBUserAlreadyOnboarded)
			},
			expectedStatus: http.StatusConflict,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.OBUserAlreadyOnboarded.Status),
				"response": map[string]interface{}{
					"errorCode": appError.OBUserAlreadyOnboarded.Code,
					"message":   appError.OBUserAlreadyOnboarded.Message,
				},
			},
		},
		{
			name: "UserNotVerified",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.AuthUserNotVerified)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.AuthUserNotVerified.Status),
				"response": map[string]interface{}{
					"errorCode": appError.AuthUserNotVerified.Code,
					"message":   appError.AuthUserNotVerified.Message,
				},
			},
		},
		{
			name: "DatabaseError",
			requestBody: om.Request{
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(false, appError.DBInsertFailed)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.DBInsertFailed.Status),
				"response": map[string]interface{}{
					"errorCode": appError.DBInsertFailed.Code,
					"message":   appError.DBInsertFailed.Message,
				},
			},
		},
		{
			name: "SuccessWithGenderZero",
			requestBody: om.Request{
				Name:   "Jane Doe",
				Age:    30,
				Gender: 0,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "User onboarded successfully",
				},
			},
		},
		{
			name: "SuccessWithMinimumAge",
			requestBody: om.Request{
				Name:   "Young User",
				Age:    13,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "User onboarded successfully",
				},
			},
		},
		{
			name: "SuccessWithMaximumAge",
			requestBody: om.Request{
				Name:   "Old User",
				Age:    100,
				Gender: 1,
			},
			mockSetup: func(svc *mocks.MockOnboardingService) {
				svc.On("OnboardUser", mock.Anything, "user1234567890", mock.AnythingOfType("onboarding.Model")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "User onboarded successfully",
				},
			},
		},
		{
			name:        "MalformedJSON",
			requestBody: `{"name": "John Doe", "age": 25, "gender": 1,}`,
			mockSetup: func(svc *mocks.MockOnboardingService) {
				// No mocks needed for JSON parsing errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.ServerBadRequest.Status),
				"response": map[string]interface{}{
					"errorCode": appError.ServerBadRequest.Code,
					"message":   appError.ServerBadRequest.Message,
				},
			},
		},
		{
			name:        "EmptyRequestBody",
			requestBody: "",
			mockSetup: func(svc *mocks.MockOnboardingService) {
				// No mocks needed for JSON parsing errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.ServerBadRequest.Status),
				"response": map[string]interface{}{
					"errorCode": appError.ServerBadRequest.Code,
					"message":   appError.ServerBadRequest.Message,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockService := new(mocks.MockOnboardingService)
			tt.mockSetup(mockService)
			handler := onboardUserHandler(mockService)

			var requestBody []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				requestBody = []byte(str)
			} else {
				requestBody, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			req := httptest.NewRequest("POST", "/api/v1/onboarding", bytes.NewBuffer(requestBody))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()

			ctx := context.WithValue(req.Context(), "requestId", "test-request-id")
			ctx = context.WithValue(ctx, user.UserIdKey, "user1234567890")
			req = req.WithContext(ctx)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			var responseBody map[string]interface{}
			err = json.Unmarshal(rr.Body.Bytes(), &responseBody)
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedBody, responseBody)

			mockService.AssertExpectations(t)
		})
	}
}

func TestRegisterOnboardingRoutes(t *testing.T) {
	mockService := new(mocks.MockOnboardingService)
	handler := onboardUserHandler(mockService)
	assert.NotNil(t, handler)
	var _ http.HandlerFunc = handler
}
