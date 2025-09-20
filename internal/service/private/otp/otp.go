package otp

import (
	"context"
	"errors"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	redisrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	otpTemplates "github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix/templates/otp"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
	otpUtils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/otp"
)

type Service struct {
	userrepo       userrepo.Repository
	redisrepo      redisrepo.Repository
	phoenixservice phoenixservice.PhoenixService
}

func New(userrepo userrepo.Repository, repo redisrepo.Repository, phoenixservice phoenixservice.PhoenixService) *Service {
	return &Service{
		userrepo:       userrepo,
		redisrepo:      repo,
		phoenixservice: phoenixservice,
	}
}

// RequestOTP Returns true if the request is successful or error otherwise
func (s *Service) RequestOTP(ctx context.Context, userId string, purpose string) (bool, error) {
	requestId := request.FromContext(ctx)
	logFields := logger.Fields{
		"userId":    userId,
		"requestId": requestId,
		"purpose":   purpose,
	}

	// Validate purpose first
	if !otpTemplates.IsValidPurpose(purpose) {
		logger.Warn("Invalid purpose provided", errors.New("invalid purpose"), appError.OtpInvalidPurpose, logFields)
		return false, appError.OtpInvalidPurpose
	}

	otp := otpUtils.GenerateOTP()
	err := s.redisrepo.SetOTP(ctx, userId, otp, 5*time.Minute, purpose)
	if err != nil {
		logger.Error("Failed to set OTP in Redis", err, appError.ServerInternalError, logFields)
		return false, appError.ServerInternalError
	}
	email, err := s.userrepo.GetUserEmailById(ctx, userId)
	if err != nil {
		logger.Error("Failed to get user email", err, appError.DBEmailQueryFailed, logFields)
		return false, appError.ServerInternalError
	}
	if email == "" {
		logger.Error("Empty email for user", errors.New("email empty for user"), appError.OtpEmptyEmailForUser, logFields)
		return false, appError.OtpEmptyEmailForUser
	}

	template, err := otpTemplates.GetTemplate(otp, purpose)

	if err != nil {
		logger.Warn("Error getting template for purpose", err, appError.ServerInternalError, logFields)
		return false, appError.ServerInternalError
	}

	err = s.phoenixservice.SendMail(ctx, userId, template)
	if err != nil {
		logger.Error("Failed to send email", err, appError.PhoenixEmailDeliveryFailed, logger.Fields{
			"userId":       userId,
			"requestId":    requestId,
			"errorMessage": err.Error(),
		})
		return false, appError.ServerInternalError
	}

	return true, nil
}

func (s *Service) VerifyOTP(ctx context.Context, userID string, code string, purpose string) (bool, error) {
	requestId := request.FromContext(ctx)
	logFields := logger.Fields{
		"userId":    userID,
		"requestId": requestId,
		"purpose":   purpose,
	}

	// Validate purpose first
	if !otpTemplates.IsValidPurpose(purpose) {
		logger.Warn("Invalid purpose provided", errors.New("invalid purpose"), appError.OtpInvalidPurpose, logFields)
		return false, appError.OtpInvalidPurpose
	}

	storedOTP, err := s.redisrepo.GetOTP(ctx, userID, purpose)
	if err != nil {
		logger.Error("Failed to get OTP from Redis", err, appError.RedisGetOtpFailed, logger.Fields{
			"userId":       userID,
			"requestId":    requestId,
			"errorMessage": err.Error(),
		})
		return false, appError.ServerInternalError
	}

	if storedOTP == "" {
		logger.Error("OTP expired or not found", errors.New("otp expired or not found"), appError.OtpExpiredOrNotFound, logger.Fields{
			"userId":    userID,
			"requestId": requestId,
		})
		return false, appError.OtpExpiredOrNotFound
	}

	if code != storedOTP {
		logger.Error("Invalid OTP provided", errors.New("invalid otp"), appError.OtpInvalid, logger.Fields{
			"userId":      userID,
			"requestId":   requestId,
			"providedOTP": code,
		})
		return false, appError.OtpInvalid
	}

	if err := s.redisrepo.DeleteOTP(ctx, userID, purpose); err != nil {
		logger.Warn("Failed to delete OTP after verification", err, appError.ServerInternalError, logger.Fields{
			"userId":    userID,
			"requestId": requestId,
			"purpose":   purpose,
		})
	}

	return true, nil
}
