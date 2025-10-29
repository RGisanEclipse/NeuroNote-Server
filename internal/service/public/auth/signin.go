package auth

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

// Signin authenticates a user and returns a JWT token.
// It checks if the user exists, verifies the password, and generates a token.
func (s *signinService) Signin(ctx context.Context, email, password string) (authModels.ServiceResponse, *appError.Code) {
	creds, err := s.userRepo.GetUserCreds(ctx, email)
	reqID := request.FromContext(ctx)

	if err != nil || creds == nil {
		logger.Error(appError.AuthEmailDoesntExist.Message, err, appError.AuthEmailDoesntExist, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    appError.AuthEmailDoesntExist.Message,
			IsVerified: false,
		}, appError.AuthEmailDoesntExist
	}

	userId := creds.Id

	isVerified, err := s.userRepo.IsUserVerified(ctx, userId)
	if err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    appError.ServerInternalError.Message,
			IsVerified: false,
		}, appError.ServerInternalError
	}
	if !isVerified {
		logger.Warn(appError.AuthUserNotVerified.Message, nil, appError.AuthUserNotVerified, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    appError.AuthUserNotVerified.Message,
			IsVerified: false,
		}, appError.AuthUserNotVerified
	}

	if !authutils.CheckPasswordHash(password, creds.PasswordHash) {
		logger.Warn(appError.AuthIncorrectPassword.Message, nil, appError.AuthIncorrectPassword, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    appError.AuthIncorrectPassword.Message,
			IsVerified: false,
		}, appError.AuthIncorrectPassword
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)
	if err != nil {
		logger.Error(appError.AuthTokenGenerationFailed.Message, err, appError.AuthTokenGenerationFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    appError.ServerInternalError.Message,
			IsVerified: false,
		}, appError.ServerInternalError
	}

	if err := s.redisRepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(appError.RedisSetRefreshTokenFailed.Message, err, appError.RedisSetRefreshTokenFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	logger.Info("User logged in successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
		"userId":    userId,
	})
	return authModels.ServiceResponse{
		Success:      true,
		Message:      "Logged in successfully",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IsVerified:   isVerified,
	}, nil
}
