package atlas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	"github.com/RGisanEclipse/AVYO-Server/internal/middleware/user"
	model "github.com/RGisanEclipse/AVYO-Server/internal/models/atlas"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/mood"
	"github.com/RGisanEclipse/AVYO-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestWeeklyMoodStripHandler_Success(t *testing.T) {
	mockService := new(mocks.MockAtlasService)
	handler := weeklyMoodStripHandler(mockService)

	happy := mood.Happy
	responseData := map[string]*mood.Type{
		"2026-01-18": &happy,
		"2026-01-19": nil,
	}

	mockService.On(
		"GetWeeklyMoodStripData",
		mock.Anything,
		mock.AnythingOfType("atlas.MoodTrendRequest"),
	).Return(&model.MoodTrendResponse{Data: responseData}, nil)

	req := httptest.NewRequest("GET", "/api/v1/mood/weekly/moodstrip", nil)
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), "requestId", "test-request-id")
	ctx = context.WithValue(ctx, user.UserIdKey, "user1234567890")
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	expectedBody := map[string]interface{}{
		"success": true,
		"status":  float64(http.StatusOK),
		"response": map[string]interface{}{
			"data": map[string]interface{}{
				"2026-01-18": "happy",
				"2026-01-19": nil,
			},
		},
	}

	assert.Equal(t, expectedBody, responseBody)
	mockService.AssertExpectations(t)
}

func TestWeeklyMoodStripHandler_MissingUserId(t *testing.T) {
	mockService := new(mocks.MockAtlasService)
	handler := weeklyMoodStripHandler(mockService)

	req := httptest.NewRequest("GET", "/api/v1/mood/weekly/moodstrip", nil)
	rr := httptest.NewRecorder()

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

func TestMonthlyTop3WidgetHandler_Success(t *testing.T) {
	mockService := new(mocks.MockAtlasService)
	handler := monthlyTopMoodsHandler(mockService)

	responseData := []model.MoodPercentage{
		{Mood: mood.Happy, Percentage: 50},
		{Mood: mood.Worried, Percentage: 30},
		{Mood: mood.Down, Percentage: 20},
	}

	mockService.On(
		"GetMonthlyTopMoodsData",
		mock.Anything,
		mock.AnythingOfType("atlas.MoodTrendRequest"),
	).Return(&model.MoodTop3Response{Data: responseData}, nil)

	req := httptest.NewRequest("GET", "/api/v1/mood/monthly/top3widget", nil)
	rr := httptest.NewRecorder()

	ctx := context.WithValue(req.Context(), "requestId", "test-request-id")
	ctx = context.WithValue(ctx, user.UserIdKey, "user1234567890")
	req = req.WithContext(ctx)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	expectedBody := map[string]interface{}{
		"success": true,
		"status":  float64(http.StatusOK),
		"response": map[string]interface{}{
			"data": []interface{}{
				map[string]interface{}{
					"mood":       "happy",
					"percentage": float64(50),
				},
				map[string]interface{}{
					"mood":       "worried",
					"percentage": float64(30),
				},
				map[string]interface{}{
					"mood":       "down",
					"percentage": float64(20),
				},
			},
		},
	}

	assert.Equal(t, expectedBody, responseBody)
	mockService.AssertExpectations(t)
}

func TestMonthlyTop3WidgetHandler_MissingUserId(t *testing.T) {
	mockService := new(mocks.MockAtlasService)
	handler := monthlyTopMoodsHandler(mockService)

	req := httptest.NewRequest("GET", "/api/v1/mood/monthly/top3widget", nil)
	rr := httptest.NewRecorder()

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
