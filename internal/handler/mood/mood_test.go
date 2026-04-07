package mood

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMoodLogHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		userId         string
		mockSetup      func(*mocks.MockMoodService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "Success_MoodOnly",
			requestBody: mood.Request{
				Mood: "happy",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
		{
			name: "Success_MoodWithReason",
			requestBody: mood.Request{
				Mood:   "worried",
				Reason: "workDeadlines",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
		{
			name:        "InvalidJSON",
			requestBody: "invalid json",
			userId:      "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
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
			userId:      "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
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
			name:        "MalformedJSON",
			requestBody: `{"mood": "happy",}`,
			userId:      "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
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
			name: "ValidationError_InvalidMood",
			requestBody: mood.Request{
				Mood: "invalid_mood",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(false, appError.MDInvalidMood)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.MDInvalidMood.Status),
				"response": map[string]interface{}{
					"errorCode": appError.MDInvalidMood.Code,
					"message":   appError.MDInvalidMood.Message,
				},
			},
		},
		{
			name: "ValidationError_EmptyMood",
			requestBody: mood.Request{
				Mood: "",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(false, appError.MDInvalidMood)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.MDInvalidMood.Status),
				"response": map[string]interface{}{
					"errorCode": appError.MDInvalidMood.Code,
					"message":   appError.MDInvalidMood.Message,
				},
			},
		},
		{
			name: "DatabaseError",
			requestBody: mood.Request{
				Mood:   "happy",
				Reason: "achievement",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(false, appError.ServerInternalError)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"success": false,
				"status":  float64(appError.ServerInternalError.Status),
				"response": map[string]interface{}{
					"errorCode": appError.ServerInternalError.Code,
					"message":   appError.ServerInternalError.Message,
				},
			},
		},
		{
			name: "Success_AllMoodTypes_Happy",
			requestBody: mood.Request{
				Mood:   "happy",
				Reason: "socialConnection",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
		{
			name: "Success_AllMoodTypes_Surprised",
			requestBody: mood.Request{
				Mood:   "surprised",
				Reason: "unexpectedNews",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
		{
			name: "Success_AllMoodTypes_Uncomfortable",
			requestBody: mood.Request{
				Mood:   "uncomfortable",
				Reason: "overwhelmed",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
		{
			name: "Success_AllMoodTypes_Down",
			requestBody: mood.Request{
				Mood:   "down",
				Reason: "exhaustion",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
		{
			name: "Success_AllMoodTypes_Frustrated",
			requestBody: mood.Request{
				Mood:   "frustrated",
				Reason: "injustice",
			},
			userId: "user1234567890",
			mockSetup: func(svc *mocks.MockMoodService) {
				svc.On("LogMood", mock.Anything, "user1234567890", mock.AnythingOfType("mood.Request")).Return(true, mocks.NoError())
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"success": true,
				"status":  float64(http.StatusOK),
				"response": map[string]interface{}{
					"success": true,
					"message": "Mood logged successfully",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(mocks.MockMoodService)
			tt.mockSetup(mockService)
			handler := moodLogHandler(mockService)

			var requestBody []byte
			var err error
			if str, ok := tt.requestBody.(string); ok {
				requestBody = []byte(str)
			} else {
				requestBody, err = json.Marshal(tt.requestBody)
				assert.NoError(t, err)
			}

			req := httptest.NewRequest("POST", "/api/v1/mood", bytes.NewBuffer(requestBody))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()

			ctx := context.WithValue(req.Context(), "requestId", "test-request-id")
			ctx = context.WithValue(ctx, user.UserIdKey, tt.userId)
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

func TestMoodLogHandler_MissingUserId(t *testing.T) {
	mockService := new(mocks.MockMoodService)
	handler := moodLogHandler(mockService)

	requestBody, _ := json.Marshal(mood.Request{Mood: "happy"})
	req := httptest.NewRequest("POST", "/api/v1/mood", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	// No userId in context
	ctx := context.WithValue(req.Context(), "requestId", "test-request-id")
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	expectedBody := map[string]interface{}{
		"success": false,
		"status":  float64(appError.AuthUnauthorized.Status),
		"response": map[string]interface{}{
			"errorCode": appError.AuthUnauthorized.Code,
			"message":   appError.AuthUnauthorized.Message,
		},
	}
	assert.Equal(t, expectedBody, responseBody)
}

func TestMoodLogHandler_EmptyUserId(t *testing.T) {
	mockService := new(mocks.MockMoodService)
	handler := moodLogHandler(mockService)

	requestBody, _ := json.Marshal(mood.Request{Mood: "happy"})
	req := httptest.NewRequest("POST", "/api/v1/mood", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	// Empty userId in context
	ctx := context.WithValue(req.Context(), "requestId", "test-request-id")
	ctx = context.WithValue(ctx, user.UserIdKey, "")
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRegisterMoodRoutes(t *testing.T) {
	mockService := new(mocks.MockMoodService)
	handler := moodLogHandler(mockService)
	assert.NotNil(t, handler)
	var _ http.HandlerFunc = handler
}
