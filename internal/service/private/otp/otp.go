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

// RequestOTP sends an OTP to the user. Returns business error or system error.
func (s *Service) RequestOTP(ctx context.Context, userId string, purpose string) (bool, *appError.Code, error) {
	requestId := request.FromContext(ctx)
	logFields := logger.Fields{
		"userId":    userId,
		"requestId": requestId,
		"purpose":   purpose,
	}

	// 1. Validate purpose
	if !otpTemplates.IsValidPurpose(purpose) {
		logger.Warn(appError.OtpInvalidPurpose.Message, nil, appError.OtpInvalidPurpose, logFields)
		return false, appError.OtpInvalidPurpose, nil
	}

	// 2. Generate OTP
	otp := otpUtils.GenerateOTP()

	// 3. Store OTP in Redis
	if err := s.redisrepo.SetOTP(ctx, userId, otp, 5*time.Minute, purpose); err != nil {
		logger.Error("Failed to set OTP in Redis", err, appError.RedisSetOtpFailed, logFields)
		return false, nil, err
	}

	email, err := s.userrepo.GetUserEmailById(ctx, userId)
	if err != nil {
		logger.Error("Failed to get user email", err, appError.DBEmailQueryFailed, logFields)
		return false, nil, err
	}
	if email == "" {
		logger.Warn("Empty email for user", errors.New("email empty for user"), appError.OtpEmptyEmailForUser, logFields)
		return false, appError.OtpEmptyEmailForUser, nil
	}

	template, err := otpTemplates.GetTemplate(otp, purpose)
	if err != nil {
		logger.Warn("Error getting template for purpose", err, appError.ServerInternalError, logFields)
		return false, nil, err
	}

	// 6. Send email
	if err := s.phoenixservice.SendMail(ctx, userId, template); err != nil {
		logger.Error("Failed to send email", err, appError.PhoenixEmailDeliveryFailed, logger.Fields{
			"userId":       userId,
			"requestId":    requestId,
			"errorMessage": err.Error(),
		})
		return false, nil, err
	}

	return true, nil, nil
}

// VerifyOTP validates the OTP for a given purpose.
// Returns business error (like invalid OTP) or system error.
func (s *Service) VerifyOTP(ctx context.Context, userID, code, purpose string) (bool, *appError.Code, error) {
	requestId := request.FromContext(ctx)
	logFields := logger.Fields{
		"userId":    userID,
		"requestId": requestId,
		"purpose":   purpose,
	}

	if !otpTemplates.IsValidPurpose(purpose) {
		logger.Warn(appError.OtpInvalidPurpose.Message, nil, appError.OtpInvalidPurpose, logFields)
		return false, appError.OtpInvalidPurpose, nil
	}

	storedOTP, err := s.redisrepo.GetOTP(ctx, userID, purpose)
	if err != nil {
		logger.Error("Failed to get OTP from Redis", err, appError.RedisGetOtpFailed, logFields)
		return false, nil, err
	}

	if storedOTP == "" {
		logger.Warn("OTP expired or not found", nil, appError.OtpExpiredOrNotFound, logFields)
		return false, appError.OtpExpiredOrNotFound, nil
	}

	if code != storedOTP {
		logger.Warn("Invalid OTP provided", nil, appError.OtpInvalid, logger.Fields{
			"userId":      userID,
			"requestId":   requestId,
			"providedOTP": code,
		})
		return false, appError.OtpInvalid, nil
	}

	if err := s.redisrepo.DeleteOTP(ctx, userID, purpose); err != nil {
		logger.Warn("Failed to delete OTP after verification", err, appError.RedisDeleteOTPFailed, logFields)
	}

	return true, nil, nil
}
