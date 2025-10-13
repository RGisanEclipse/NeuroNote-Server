package auth

import (
	"context"
	"errors"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
	"gorm.io/gorm"
)

func (s *forgotPasswordService) ResetPassword(ctx context.Context, userId string, password string) (authModels.ResetPasswordResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}
	exists, err := s.userRepo.UserExistsById(ctx, userId)
	if err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}
	if !exists {
		logger.Warn(appError.AuthUserNotFound.Message, nil, appError.AuthUserNotFound, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: appError.AuthUserNotFound.Message,
		}, appError.AuthUserNotFound
	}

	isVerified, err := s.redisRepo.CheckPasswordResetFlag(ctx, userId)

	if err != nil {
		logger.Warn(appError.RedisSetPasswordResetKeyFailed.Message, err, appError.RedisSetPasswordResetKeyFailed, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	if !isVerified {
		logger.Warn(appError.AuthPasswordOtpNotVerified.Message, nil, appError.AuthPasswordOtpNotVerified, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: appError.AuthPasswordOtpNotVerified.Message,
		}, appError.AuthPasswordOtpNotVerified
	}

	err = authModels.ValidatePassword(password)
	if err != nil {
		logger.Warn("Password reset attempt with weak password", nil, appError.PasswordTooShort, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: "Password doesn't match the required criteria",
		}, appError.PasswordTooShort
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(appError.AuthPasswordHashingFailed.Message, err, appError.AuthPasswordHashingFailed, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	err = s.userRepo.ResetPassword(ctx, userId, hash)

	if err != nil {
		logger.Warn(appError.DBUpdateFailed.Message, err, appError.DBUpdateFailed, logFields)

		return authModels.ResetPasswordResponse{
			Success: false,
			Message: "Failed to reset password",
		}, appError.DBUpdateFailed
	}

	err = s.redisRepo.DeletePasswordResetFlag(ctx, userId)

	if err != nil {
		logger.Warn(appError.RedisSetPasswordResetKeyFailed.Message, err, appError.RedisSetPasswordResetKeyFailed, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	return authModels.ResetPasswordResponse{
		Success: true,
		Message: "Password Reset successfully",
	}, nil
}

func (s *forgotPasswordService) ForgotPasswordOTP(ctx context.Context, email string) (authModels.ForgotPasswordOTPResponse, *appError.Code) {
	reqID := request.FromContext(ctx)
	creds, err := s.userRepo.GetUserCreds(ctx, email)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warn("Password reset requested for non-existing email", nil, appError.AuthEmailDoesntExist, logger.Fields{
				"requestId": reqID,
				"email":     email,
			})
			return authModels.ForgotPasswordOTPResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
			}, appError.AuthEmailDoesntExist
		}
		return authModels.ForgotPasswordOTPResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	userId := creds.Id
	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}

	success, logicalError, sysErr := s.otpService.RequestOTP(ctx, userId, "forgot_password")

	if sysErr != nil {
		logger.Error("Failed to send OTP due to system error", sysErr, appError.AuthOtpSendFailure, logFields)
		return authModels.ForgotPasswordOTPResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	if logicalError != nil {
		logger.Warn("Failed to send OTP due to logical error", logicalError, logicalError, logFields)
		return authModels.ForgotPasswordOTPResponse{
			Success: false,
			Message: logicalError.Message,
		}, logicalError
	}

	logger.Info("Forgot Password OTP sent successfully", logFields)

	return authModels.ForgotPasswordOTPResponse{
		Success: success,
		Message: "OTP sent successfully",
		UserId:  userId,
	}, nil
}

func (s *forgotPasswordService) ForgotPasswordOTPVerify(ctx context.Context, userId, otp string) (authModels.ForgotPasswordResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}

	if userId == "" || otp == "" {
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: appError.ServerBadRequest.Message,
		}, appError.ServerBadRequest
	}

	// Now returns success, logicalError, sysErr like SignupOTPVerify
	success, logicalError, sysErr := s.otpService.VerifyOTP(ctx, userId, otp, "forgot_password")

	if sysErr != nil {
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: "Internal server error",
		}, appError.ServerInternalError
	}

	if logicalError != nil {
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: logicalError.Message,
		}, logicalError
	}

	redisErr := s.redisRepo.SetPasswordResetFlag(ctx, userId, ResetPasswordExpiry)
	if redisErr != nil {
		logger.Warn(appError.RedisSetPasswordResetKeyFailed.Message, redisErr, appError.RedisSetPasswordResetKeyFailed, logFields)
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	logger.Info("Forgot Password OTP verified successfully", logFields)

	return authModels.ForgotPasswordResponse{
		Success: success,
		Message: "OTP verified successfully",
		UserId:  userId,
	}, nil
}
