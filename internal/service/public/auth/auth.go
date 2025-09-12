package auth

import (
	"context"
	"errors"
	"time"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	redisrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	dbErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	serverErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
	otpService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
)

type Service struct {
	userrepo userrepo.Repository
	redisrepo redisrepo.Repository
	otpService otpService.OTPService
}

const RefreshTokenExpiry = 7 * 24 * time.Hour

func New(userrepo userrepo.Repository, redisrepo redisrepo.Repository, otpService otpService.OTPService) *Service { return &Service{userrepo, redisrepo, otpService} }

// Signup registers a new user and returns a JWT token.
// It checks if the email is already taken, hashes the password, creates the user
func (s *Service) Signup(ctx context.Context, email, password string) (authModels.AuthServiceResponse, error) {

	exists, err := s.userrepo.UserExists(ctx, email)
	reqID := request.FromContext(ctx)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err)
		return authModels.AuthServiceResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}
	if exists {
        logger.Info(authErr.AuthError.EmailExists, logger.Fields{
			"email":     email,
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success: false,
			Message: authErr.AuthError.EmailExists,
		}, errors.New(authErr.AuthError.EmailExists)
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(authErr.AuthError.PasswordHashingFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}
	// Generate a unique user ID (e.g., UUID or similar)
	userId := authutils.GenerateUserId()
	success, err := s.userrepo.CreateUser(ctx, email, hash, userId)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success: success,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)

	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}
	
	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.RedisError.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	logger.Info("Account created successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
		"userId":    userId,
	})
	return authModels.AuthServiceResponse{
		Success: true,
		Message: "Account created successfully",
		AccessToken:   accessToken,
		RefreshToken: refreshToken,
		IsVerified: false,
	}, nil
}

// Signin authenticates a user and returns a JWT token.
// It checks if the user exists, verifies the password, and generates a token.    
func (s *Service) Signin(ctx context.Context, email, password string) (authModels.AuthServiceResponse, error) {
	creds, err := s.userrepo.GetUserCreds(ctx, email)
	reqID := request.FromContext(ctx)

	if err != nil || creds == nil {
		logger.Error(authErr.AuthError.EmailDoesntExist, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success:    false,
			Message:    authErr.AuthError.EmailDoesntExist,
			IsVerified: false,
		}, errors.New(authErr.AuthError.EmailDoesntExist)
	}

	userId := creds.Id

	isVerified, err := s.userrepo.IsUserVerified(ctx, userId)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success:    false,
			Message:    serverErr.ServerError.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	if !authutils.CheckPasswordHash(password, creds.PasswordHash) {
		logger.Warn(authErr.AuthError.IncorrectPassword, nil, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success:    false,
			Message:    authErr.AuthError.IncorrectPassword,
			IsVerified: false,
		}, errors.New(authErr.AuthError.IncorrectPassword)
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)
	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success:    false,
			Message:    serverErr.ServerError.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.RedisError.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthServiceResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	logger.Info("User logged in successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
		"userId":    userId,
	})
	return authModels.AuthServiceResponse{
		Success:    true,
		Message:    "Logged in successfully",
		AccessToken: accessToken,
		RefreshToken: refreshToken,
		IsVerified: isVerified,
	}, nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (authModels.RefreshTokenServiceResponse, error) {
	reqID := request.FromContext(ctx)

	claims, err := authutils.VerifyAuthToken(refreshToken)
	if err != nil {
		logger.Warn(authErr.AuthError.InvalidRefreshToken, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(authErr.AuthError.InvalidRefreshToken)
	}

	userId := claims.UserID
	email := claims.Email
	if userId == "" || email == "" {
		logger.Error("Refresh token missing required claims", nil, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(authErr.AuthError.InvalidRefreshToken)
	}

	storedToken, err := s.redisrepo.GetRefreshToken(ctx, userId)
	if err != nil || storedToken != refreshToken {
		logger.Warn(authErr.AuthError.RefreshTokenMismatch, err, logger.Fields{
			"requestId":    reqID,
			"storedToken":  storedToken,
			"providedToken": refreshToken,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(authErr.AuthError.RefreshTokenMismatch)
	}

	// Immediately delete the used refresh token to prevent reuse
	if err := s.redisrepo.DeleteRefreshToken(ctx, userId); err != nil {
		logger.Error("Failed to delete used refresh token", err, logger.Fields{
			"requestId": reqID,
			"userId":    userId,
		})
	}

	newAccessToken, newRefreshToken, err := authutils.GenerateTokenPair(userId, email)
	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(serverErr.ServerError.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, newRefreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.RedisError.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(serverErr.ServerError.InternalError)
	}

	logger.Info("Refresh token generated successfully", logger.Fields{
		"requestId": reqID,
		"userId":    userId,
		"oldTokenExpiry": claims.ExpiresAt.Time,
	})
	
	return authModels.RefreshTokenServiceResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *Service) SignupOTP(ctx context.Context, userId string) (authModels.SignupOTPResponse, error) {
    reqID := request.FromContext(ctx)

    logFields := logger.Fields{
        "userId":    userId,
        "requestId": reqID,
        "purpose":   otpService.OTPPurposeSignup,
    }

    success, err := s.otpService.RequestOTP(ctx, userId, string(otpService.OTPPurposeSignup))
    if err != nil {
        logger.Error("Failed to send OTP due to service error", err, logFields)
        return authModels.SignupOTPResponse{
            Success: false,
            Message: authErr.AuthError.InternalServiceError,
        }, err
    }

    if !success {
        logger.Warn("OTP service returned unsuccessful result", nil, logFields)
        return authModels.SignupOTPResponse{
            Success: false,
            Message: authErr.AuthError.OTPSendFailure, 
        }, nil
    }

    logger.Info("Signup OTP sent successfully", logFields)

    return authModels.SignupOTPResponse{
        Success: true,
        Message: "OTP sent successfully",
    }, nil
}

func (s *Service) SignupOTPVerify(ctx context.Context, userId, otp string) (authModels.SignupOTPResponse, error) {
    reqID := request.FromContext(ctx)

    logFields := logger.Fields{
        "userId":    userId,
        "requestId": reqID,
        "purpose":   otpService.OTPPurposeSignup,
    }

    success, err := s.otpService.VerifyOTP(ctx, userId, otp, string(otpService.OTPPurposeSignup))
    if err != nil {
        logger.Error("Failed to verify OTP due to service error", err, logFields)
        return authModels.SignupOTPResponse{
            Success: false,
            Message: authErr.AuthError.InternalServiceError,
        }, err
    }

    if !success {
        logger.Warn("OTP verification failed", nil, logFields)
        return authModels.SignupOTPResponse{
            Success: false,
            Message: authErr.AuthError.OTPVerificationFailure,
        }, nil
    }
	err = s.userrepo.MarkUserVerified(ctx, userId)

	if err != nil{
		logger.Warn(dbErr.DBError.UpdateFailed, err, logFields)
		
		return authModels.SignupOTPResponse{
			Success: false,
			Message: "Failed to mark user as verified",
		}, nil
	}
    
	logger.Info("Signup OTP verified successfully", logFields)

    return authModels.SignupOTPResponse{
        Success: true,
        Message: "OTP verified successfully",
    }, nil
}