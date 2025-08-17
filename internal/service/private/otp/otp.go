package otp

import (
	"context"
	"errors"
	"time"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"

	redisrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	models "github.com/RGisanEclipse/NeuroNote-Server/internal/models/otp"
	emailtemplates "github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix/templates"
	otpUtils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/otp"
	dbErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	otpErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/otp"
	phoenixErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/phoenix"
	serverErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
)

type Service struct {
	userrepo userrepo.Repository
	redisrepo redisrepo.Repository
	phoenixservice phoenixservice.PhoenixService
}

func New(userrepo userrepo.Repository, repo redisrepo.Repository, phoenixservice phoenixservice.PhoenixService) *Service {
	return &Service{
		userrepo: userrepo,
		redisrepo: repo,
		phoenixservice: phoenixservice,
	}
}

func (s *Service) RequestOTP(ctx context.Context, userId string, purpose string) (*models.OTPResponse, error) {
	requestId := request.FromContext(ctx)
	otp := otpUtils.GenerateOTP()
	err := s.redisrepo.SetOTP(ctx, userId, otp, 5*time.Minute, purpose)
	if err != nil {
		logger.Error("Failed to set OTP in Redis", err, logger.Fields{
			"userId": userId,
			"requestId": requestId,
		})
		return nil, errors.New(serverErr.ServerError.InternalError)
	}
	email, err := s.userrepo.GetUserEmailById(ctx, userId)
	if err != nil {
		logger.Error(dbErr.DBError.EmailQueryFailed, err, logger.Fields{
			"userId": userId,
			"requestId": requestId,
		})
		return nil, errors.New(serverErr.ServerError.InternalError)
	}
	if email == "" {
		logger.Error(otpErr.OTPError.EmptyEmailForUser, nil, logger.Fields{
			"userId": userId,
			"requestId": requestId,
		})
		return nil, errors.New(serverErr.ServerError.InternalError)
	}
	
	template := emailtemplates.GetOTPTemplate(otp)
	err = s.phoenixservice.SendMail(ctx, userId, template)
	if err != nil {
		logger.Error(phoenixErr.PhoenixErrorMessages.EmailDeliveryFailed, err, logger.Fields{
			"userId": userId,
			"requestId": requestId,
			"errorMessage": err.Error(),
		})
		return nil, errors.New(serverErr.ServerError.InternalError)
	}
	
	return &models.OTPResponse{
		Success: true,
		Message: "OTP sent successfully",
	}, nil
}

func (s *Service) VerifyOTP(ctx context.Context, userID string, code string, purpose string) (*models.OTPResponse, error) {
	requestId := request.FromContext(ctx)
	storedOTP, err := s.redisrepo.GetOTP(ctx, userID, purpose)
	if err != nil {
		logger.Error(dbErr.RedisError.GetOTPFailed, err, logger.Fields{
			"userId": userID,
			"requestId": requestId,
			"errorMessage": dbErr.RedisError.GetOTPFailed,
		})
		return nil, errors.New(serverErr.ServerError.InternalError)
	}

	if storedOTP == "" {
		logger.Error(otpErr.OTPError.OTPExpiredOrNotFound, nil, logger.Fields{
			"userId": userID,
			"requestId": requestId,
		})
		return &models.OTPResponse{
			Success: false,
			Message: otpErr.OTPError.OTPExpiredOrNotFound,
		}, errors.New(otpErr.OTPError.OTPExpiredOrNotFound)
	}

	if code != storedOTP {
		logger.Error(otpErr.OTPError.InvalidOTP, nil, logger.Fields{
			"userId": userID,
			"requestId": requestId,
			"providedOTP": code,
		})
		return &models.OTPResponse{
			Success: false,
			Message: otpErr.OTPError.InvalidOTP,
		}, errors.New(otpErr.OTPError.InvalidOTP)
	}

	_ = s.redisrepo.DeleteOTP(ctx, userID, purpose)

	return &models.OTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}, nil
}