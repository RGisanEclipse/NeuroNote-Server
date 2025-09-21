package auth

import (
	"context"
	"errors"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	redisrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	otpService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
	"gorm.io/gorm"
)

type Service struct {
	userrepo   userrepo.Repository
	redisrepo  redisrepo.Repository
	otpService otpService.S
}

const RefreshTokenExpiry = 7 * 24 * time.Hour
const ResetPasswordExpiry = 10 * time.Minute

func New(userrepo userrepo.Repository, redisrepo redisrepo.Repository, otpService otpService.S) *Service {
	return &Service{userrepo, redisrepo, otpService}
}

// Signup registers a new user and returns a JWT token.
// It checks if the email is already taken, hashes the password, creates the user
func (s *Service) Signup(ctx context.Context, email, password string) (authModels.ServiceResponse, *appError.Code) {

	exists, err := s.userrepo.UserExists(ctx, email)
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
	success, err := s.userrepo.CreateUser(ctx, email, hash, userId)
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

	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
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

// Signin authenticates a user and returns a JWT token.
// It checks if the user exists, verifies the password, and generates a token.
func (s *Service) Signin(ctx context.Context, email, password string) (authModels.ServiceResponse, *appError.Code) {
	creds, err := s.userrepo.GetUserCreds(ctx, email)
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

	isVerified, err := s.userrepo.IsUserVerified(ctx, userId)
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

	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
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

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (authModels.RefreshTokenServiceResponse, *appError.Code) {
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

	storedToken, err := s.redisrepo.GetRefreshToken(ctx, userId)
	if err != nil || storedToken != refreshToken {
		logger.Warn(appError.AuthRefreshTokenMismatch.Message, err, appError.AuthRefreshTokenMismatch, logger.Fields{
			"requestId":     reqID,
			"storedToken":   storedToken,
			"providedToken": refreshToken,
		})
		return authModels.RefreshTokenServiceResponse{}, appError.AuthRefreshTokenMismatch
	}

	// Immediately delete the used refresh token to prevent reuse
	if err := s.redisrepo.DeleteRefreshToken(ctx, userId); err != nil {
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

	if err := s.redisrepo.SetRefreshToken(ctx, userId, newRefreshToken, RefreshTokenExpiry); err != nil {
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

func (s *Service) SignupOTP(ctx context.Context, userId string) (authModels.GenericOTPResponse, *appError.Code) {
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

func (s *Service) SignupOTPVerify(ctx context.Context, userId, otp string) (authModels.GenericOTPResponse, *appError.Code) {
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

	dbErr := s.userrepo.MarkUserVerified(ctx, userId)

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

func (s *Service) ForgotPasswordOTP(ctx context.Context, email string) (authModels.GenericOTPResponse, *appError.Code) {
	reqID := request.FromContext(ctx)
	creds, err := s.userrepo.GetUserCreds(ctx, email)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warn("Password reset requested for non-existing email", nil, appError.AuthEmailDoesntExist, logger.Fields{
				"requestId": reqID,
				"email":     email,
			})
			return authModels.GenericOTPResponse{
				Success: false,
				Message: appError.AuthEmailDoesntExist.Message,
			}, appError.AuthEmailDoesntExist
		}
		return authModels.GenericOTPResponse{
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
		logger.Error("Failed to send OTP due to system error", sysErr, nil, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: appError.ServerInternalError.Message,
		}, appError.ServerInternalError
	}

	if logicalError != nil {
		logger.Warn("Failed to send OTP due to logical error", logicalError, logicalError, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: logicalError.Message,
		}, logicalError
	}

	logger.Info("Forgot Password OTP sent successfully", logFields)

	return authModels.GenericOTPResponse{
		Success: success,
		Message: "OTP sent successfully",
	}, nil
}

func (s *Service) ForgotPasswordOTPVerify(ctx context.Context, userId, otp string) (authModels.ForgotPasswordResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
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

	redisErr := s.redisrepo.SetPasswordResetFlag(ctx, userId, ResetPasswordExpiry)
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

func (s *Service) ResetPassword(ctx context.Context, userId string, password string) (authModels.ResetPasswordResponse, *appError.Code) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}
	exists, err := s.userrepo.UserExists(ctx, userId)
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

	isVerified, err := s.redisrepo.CheckPasswordResetFlag(ctx, userId)

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

	err = s.userrepo.ResetPassword(ctx, userId, hash)

	if err != nil {
		logger.Warn(appError.DBUpdateFailed.Message, err, appError.DBUpdateFailed, logFields)

		return authModels.ResetPasswordResponse{
			Success: false,
			Message: "Failed to reset password",
		}, appError.DBUpdateFailed
	}

	err = s.redisrepo.DeletePasswordResetFlag(ctx, userId)

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
