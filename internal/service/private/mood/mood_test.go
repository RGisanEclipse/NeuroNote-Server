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
