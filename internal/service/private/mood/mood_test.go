package mood

import (
	"context"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_LogMood(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		request        mood.Request
		mockSetup      func(*mocks.MockMoodRepo)
		expectedResult bool
		expectedError  *appError.Code
	}{
		{
			name:   "Success_MoodOnly",
			userId: "user1234567890",
			request: mood.Request{
				Mood: "happy",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_MoodWithReason",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "happy",
				Reason: "achievement",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_DownMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "down",
				Reason: "loneliness",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_WorriedMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "worried",
				Reason: "workDeadlines",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_FrustratedMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "frustrated",
				Reason: "frustration",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_UncomfortableMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "uncomfortable",
				Reason: "socialPressure",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_SurprisedMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "surprised",
				Reason: "unexpectedNews",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_ReasonWithWhitespace",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "happy",
				Reason: "   ",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "ValidationError_InvalidMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood: "invalid_mood",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.MDInvalidMood,
		},
		{
			name:   "ValidationError_EmptyMood",
			userId: "user1234567890",
			request: mood.Request{
				Mood: "",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.MDInvalidMood,
		},
		{
			name:   "ValidationError_MoodWithTypo",
			userId: "user1234567890",
			request: mood.Request{
				Mood: "hapy",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.MDInvalidMood,
		},
		{
			name:   "DatabaseError_SaveFailed",
			userId: "user1234567890",
			request: mood.Request{
				Mood:   "happy",
				Reason: "achievement",
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.AnythingOfType("mood.Entry")).Return(assert.AnError)
			},
			expectedResult: false,
			expectedError:  appError.ServerInternalError,
		},
		{
			name:   "Success_WithOfflineTimestamp",
			userId: "user1234567890",
			request: mood.Request{
				Mood:      "happy",
				Reason:    "achievement",
				Timestamp: 1700000000,
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.MatchedBy(func(e mood.Entry) bool {
					return e.CreatedAt == 1700000000
				})).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "Success_ZeroTimestampUsesServerTime",
			userId: "user1234567890",
			request: mood.Request{
				Mood:      "happy",
				Timestamp: 0,
			},
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("SaveMood", mock.Anything, mock.MatchedBy(func(e mood.Entry) bool {
					// CreatedAt 0 means GORM auto-fills — entry arrives with 0, not set by service
					return e.CreatedAt == 0
				})).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			moodRepo := new(mocks.MockMoodRepo)

			// Setup mocks
			tt.mockSetup(moodRepo)

			// Create the service
			service := NewService(moodRepo)

			// Test the service method
			result, errCode := service.LogMood(context.Background(), tt.userId, tt.request)

			// Verify results
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedError, errCode)

			// Verify mock expectations
			moodRepo.AssertExpectations(t)
		})
	}
}

func TestService_GetMood(t *testing.T) {
	reason := mood.ReasonType("achievement")
	entries := []mood.Entry{
		{
			ID:        "entry-1",
			UserID:    "user1234567890",
			Mood:      mood.Type("happy"),
			Reason:    &reason,
			CreatedAt: 1700000000,
		},
	}

	tests := []struct {
		name          string
		userId        string
		days          int
		mockSetup     func(*mocks.MockMoodRepo)
		expectedData  []mood.Entry
		expectedError *appError.Code
	}{
		{
			name:   "Success_WithEntries",
			userId: "user1234567890",
			days:   7,
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("GetMoodByDuration", mock.Anything, "user1234567890", mock.AnythingOfType("int64")).Return(entries, nil)
			},
			expectedData:  entries,
			expectedError: mocks.NoError(),
		},
		{
			name:   "ValidationError_InvalidDays",
			userId: "user1234567890",
			days:   0,
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				// No repo calls expected
			},
			expectedData:  nil,
			expectedError: appError.MDInvalidDaysRange,
		},
		{
			name:   "DatabaseError",
			userId: "user1234567890",
			days:   7,
			mockSetup: func(moodRepo *mocks.MockMoodRepo) {
				moodRepo.On("GetMoodByDuration", mock.Anything, "user1234567890", mock.AnythingOfType("int64")).Return(nil, assert.AnError)
			},
			expectedData:  nil,
			expectedError: appError.ServerInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			moodRepo := new(mocks.MockMoodRepo)

			tt.mockSetup(moodRepo)

			service := NewService(moodRepo)

			result, errCode := service.GetMood(context.Background(), tt.userId, tt.days)

			assert.Equal(t, tt.expectedData, result)
			assert.Equal(t, tt.expectedError, errCode)

			moodRepo.AssertExpectations(t)
		})
	}
}
