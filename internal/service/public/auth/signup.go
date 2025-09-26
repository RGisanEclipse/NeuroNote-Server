package auth

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

// Signup registers a new user and returns a JWT token.
// It checks if the email is already taken, hashes the password, creates the user
func (s *signupService) Signup(ctx context.Context, email, password string) (authModels.ServiceResponse, *appError.Code) {

	exists, err := s.userRepo.UserExists(ctx, email)
	reqID := request.FromContext(ctx)
	if err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}
	if exists {
		logger.Warn(appError.AuthEmailExists.Message, err, appError.AuthEmailExists, logger.Fields{
			"email":     email,
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: appError.AuthEmailExists.Message,
		}, appError.AuthEmailExists
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(appError.AuthPasswordHashingFailed.Message, err, appError.AuthPasswordHashingFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}
	// Generate a unique user ID (e.g., UUID or similar)
	userId := authutils.GenerateUserId()
	success, err := s.userRepo.CreateUser(ctx, email, hash, userId)
	if err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: success,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)

	if err != nil {
		logger.Error(appError.AuthTokenGenerationFailed.Message, err, appError.AuthTokenGenerationFailed, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
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

	logger.Info("Account created successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
		"userId":    userId,
	})
	return authModels.ServiceResponse{
		Success:      true,
		Message:      "Account created successfully",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IsVerified:   false,
	}, nil
}

func (s *signupService) SignupOTP(ctx context.Context, userId string) (authModels.GenericOTPResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "signup",
	}

	success, errCode, err := s.otpService.RequestOTP(ctx, userId, "signup")

	if errCode != nil {
		logger.Warn("OTP service returned business error", nil, errCode, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: errCode.Message,
		}, errCode
	}

	if err != nil {
		logger.Error("Failed to send OTP due to service error", err, appError.ServerInternalError, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: err.Error(),
		}, appError.ServerInternalError
	}

	if !success {
		logger.Warn("OTP service returned unsuccessful result", nil, appError.AuthOtpSendFailure, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: appError.AuthOtpSendFailure.Message,
		}, appError.AuthOtpSendFailure
	}

	logger.Info("Signup OTP sent successfully", logFields)

	return authModels.GenericOTPResponse{
		Success: true,
		Message: "OTP sent successfully",
	}, nil
}

func (s *signupService) SignupOTPVerify(ctx context.Context, userId, otp string) (authModels.GenericOTPResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "signup",
	}

	success, logicalError, sysErr := s.otpService.VerifyOTP(ctx, userId, otp, "signup")

	if sysErr != nil {
		return authModels.GenericOTPResponse{
			Success: false,
			Message: "Internal server error",
		}, appError.ServerInternalError
	}

	if logicalError != nil {
		return authModels.GenericOTPResponse{
			Success: false,
			Message: logicalError.Message,
		}, logicalError
	}

	dbErr := s.userRepo.MarkUserVerified(ctx, userId)

	if dbErr != nil {
		logger.Warn(appError.DBUpdateFailed.Message, dbErr, appError.DBUpdateFailed, logFields)

		return authModels.GenericOTPResponse{
			Success: false,
			Message: "Failed to mark user as verified",
		}, appError.DBUpdateFailed
	}

	logger.Info("Signup OTP verified successfully", logFields)

	return authModels.GenericOTPResponse{
		Success: success,
		Message: "OTP verified successfully",
	}, nil
}
