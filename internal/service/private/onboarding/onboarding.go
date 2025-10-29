package onboarding

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
)

// OnboardUser returns success and an error and onboards the user into onboarding.details db
func (s *service) OnboardUser(ctx context.Context, userId string, onboardingData om.Model) (bool, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId": userId,
		"reqId":  reqID,
	}

	logger.Info("Onboarding Request", logger.Fields{
		"userId":         userId,
		"reqID":          reqID,
		"onboardingData": onboardingData,
	})

	if err := ValidateOnboardingData(onboardingData); err != nil {
		logger.Warn("Validation failed", nil, err, logFields)
		return false, err
	}

	exists, err := s.userRepo.UserExistsById(ctx, userId)
	if err != nil {
		logger.Error(appError.DBUserQueryFailed.Message, err, appError.DBUserQueryFailed, logFields)
		return false, appError.DBUserQueryFailed
	}
	if !exists {
		logger.Warn(appError.AuthUserNotFound.Message, nil, appError.AuthUserNotFound, logFields)
		return false, appError.AuthUserNotFound
	}

	isOnboardedAlready, err := s.onboardingRepo.IsOnboardedAlready(ctx, userId)
	if err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logFields)
		return false, appError.DBQueryFailed
	}
	if isOnboardedAlready {
		logger.Warn(appError.OBUserAlreadyOnboarded.Message, nil, appError.OBUserAlreadyOnboarded, logFields)
		return false, appError.OBUserAlreadyOnboarded
	}

	isVerified, err := s.userRepo.IsUserVerified(ctx, userId)
	if err != nil {
		logger.Error(appError.DBUserQueryFailed.Message, err, appError.DBUserQueryFailed, logFields)
		return false, appError.DBUserQueryFailed
	}
	if !isVerified {
		logger.Warn(appError.AuthUserNotVerified.Message, nil, appError.AuthUserNotVerified, logFields)
		return false, appError.AuthUserNotVerified
	}

	err = s.onboardingRepo.SaveOnboardingDetails(ctx, onboardingData)
	if err != nil {
		logger.Error(appError.DBInsertFailed.Message, err, appError.DBInsertFailed, logFields)
		return false, appError.DBInsertFailed
	}

	logger.Info("User successfully onboarded", logFields)
	return true, nil
}
