package onboarding

import (
	"context"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestService_OnboardUser(t *testing.T) {
	tests := []struct {
		name           string
		userId         string
		onboardingData om.Model
		mockSetup      func(*mocks.MockUserRepo, *mocks.MockOnboardingRepo)
		expectedResult bool
		expectedError  *appError.Code
	}{
		{
			name:   "Success",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("SaveOnboardingDetails", mock.Anything, mock.AnythingOfType("onboarding.Model")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "ValidationError_EmptyName",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.OBNameTooShort,
		},
		{
			name:   "ValidationError_NameTooLong",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "ThisIsAVeryLongNameThatExceedsFiftyCharactersAndShouldFailValidation",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.OBNameTooLong,
		},
		{
			name:   "ValidationError_AgeTooYoung",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    12,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.OBInvalidAge,
		},
		{
			name:   "ValidationError_AgeTooOld",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    101,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.OBInvalidAge,
		},
		{
			name:   "ValidationError_InvalidGender",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 2,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				// No mocks needed for validation errors
			},
			expectedResult: false,
			expectedError:  appError.OBInvalidGender,
		},
		{
			name:   "UserNotFound",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(false, nil)
			},
			expectedResult: false,
			expectedError:  appError.AuthUserNotFound,
		},
		{
			name:   "UserExistsCheckFailed",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(false, assert.AnError)
			},
			expectedResult: false,
			expectedError:  appError.DBUserQueryFailed,
		},
		{
			name:   "UserAlreadyOnboarded",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(true, nil)
			},
			expectedResult: false,
			expectedError:  appError.OBUserAlreadyOnboarded,
		},
		{
			name:   "OnboardedCheckFailed",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, assert.AnError)
			},
			expectedResult: false,
			expectedError:  appError.DBQueryFailed,
		},
		{
			name:   "UserNotVerified",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(false, nil)
			},
			expectedResult: false,
			expectedError:  appError.AuthUserNotVerified,
		},
		{
			name:   "UserVerificationCheckFailed",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(false, assert.AnError)
			},
			expectedResult: false,
			expectedError:  appError.DBUserQueryFailed,
		},
		{
			name:   "SaveOnboardingDetailsFailed",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "John Doe",
				Age:    25,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("SaveOnboardingDetails", mock.Anything, mock.AnythingOfType("onboarding.Model")).Return(assert.AnError)
			},
			expectedResult: false,
			expectedError:  appError.DBInsertFailed,
		},
		{
			name:   "SuccessWithGenderZero",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "Jane Doe",
				Age:    30,
				Gender: 0,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("SaveOnboardingDetails", mock.Anything, mock.AnythingOfType("onboarding.Model")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "SuccessWithMinimumAge",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "Young User",
				Age:    13,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("SaveOnboardingDetails", mock.Anything, mock.AnythingOfType("onboarding.Model")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
		{
			name:   "SuccessWithMaximumAge",
			userId: "user1234567890",
			onboardingData: om.Model{
				UserID: "user1234567890",
				Name:   "Old User",
				Age:    100,
				Gender: 1,
			},
			mockSetup: func(userRepo *mocks.MockUserRepo, onboardingRepo *mocks.MockOnboardingRepo) {
				userRepo.On("UserExistsById", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("IsOnboardedAlready", mock.Anything, "user1234567890").Return(false, nil)
				userRepo.On("IsUserVerified", mock.Anything, "user1234567890").Return(true, nil)
				onboardingRepo.On("SaveOnboardingDetails", mock.Anything, mock.AnythingOfType("onboarding.Model")).Return(nil)
			},
			expectedResult: true,
			expectedError:  mocks.NoError(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := new(mocks.MockUserRepo)
			onboardingRepo := new(mocks.MockOnboardingRepo)

			// Setup mocks
			tt.mockSetup(userRepo, onboardingRepo)

			// Create the service
			service := NewService(userRepo, onboardingRepo)

			// Test the service method
			result, errCode := service.OnboardUser(context.Background(), tt.userId, tt.onboardingData)

			// Verify results
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedError, errCode)

			// Verify mock expectations
			userRepo.AssertExpectations(t)
			onboardingRepo.AssertExpectations(t)
		})
	}
}
