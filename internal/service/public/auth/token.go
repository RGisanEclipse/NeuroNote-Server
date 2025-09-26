package auth

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

func (s *signinService) RefreshToken(ctx context.Context, refreshToken string) (authModels.RefreshTokenServiceResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	claims, err := authutils.VerifyAuthToken(refreshToken)
	if err != nil {
		logger.Warn(appError.AuthInvalidRefreshToken.Message, err, appError.AuthInvalidRefreshToken, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, appError.AuthInvalidRefreshToken
	}

	userId := claims.UserID
	email := claims.Email
	if userId == "" || email == "" {
		logger.Error("Refresh token missing required claims", nil, appError.AuthInvalidRefreshToken, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, appError.AuthInvalidRefreshToken
	}

	storedToken, err := s.redisRepo.GetRefreshToken(ctx, userId)
	if err != nil || storedToken != refreshToken {
		logger.Warn(appError.AuthRefreshTokenMismatch.Message, err, appError.AuthRefreshTokenMismatch, logger.Fields{
			"requestId":     reqID,
			"storedToken":   storedToken,
			"providedToken": refreshToken,
		})
		return authModels.RefreshTokenServiceResponse{}, appError.AuthRefreshTokenMismatch
	}

	// Immediately delete the used refresh token to prevent reuse
	if err := s.redisRepo.DeleteRefreshToken(ctx, userId); err != nil {
		logger.Error("Failed to delete used refresh token", err, appError.RedisDeleteRefreshTokenFailed, logger.Fields{
			"requestId": reqID,
			"userId":    userId,
		})
	}

	newAccessToken, newRefreshToken, err := authutils.GenerateTokenPair(userId, email)
	if err != nil {
		logger.Error(appError.AuthTokenGenerationFailed.Message, err, appError.AuthTokenGenerationFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, appError.ServerInternalError
	}

	if err := s.redisRepo.SetRefreshToken(ctx, userId, newRefreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(appError.RedisSetRefreshTokenFailed.Message, err, appError.RedisSetRefreshTokenFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, appError.ServerInternalError
	}

	logger.Info("Refresh token generated successfully", logger.Fields{
		"requestId":      reqID,
		"userId":         userId,
		"oldTokenExpiry": claims.ExpiresAt.Time,
	})

	return authModels.RefreshTokenServiceResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
