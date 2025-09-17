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
func (s *Service) Signup(ctx context.Context, email, password string) (authModels.ServiceResponse, error) {

	exists, err := s.userrepo.UserExists(ctx, email)
	reqID := request.FromContext(ctx)
	if err != nil {
		logger.Error(dbErr.Error.QueryFailed, err)
		return authModels.ServiceResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}
	if exists {
		logger.Info(authErr.Error.EmailExists, logger.Fields{
			"email":     email,
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: authErr.Error.EmailExists,
		}, errors.New(authErr.Error.EmailExists)
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(authErr.Error.PasswordHashingFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}
	// Generate a unique user ID (e.g., UUID or similar)
	userId := authutils.GenerateUserId()
	success, err := s.userrepo.CreateUser(ctx, email, hash, userId)
	if err != nil {
		logger.Error(dbErr.Error.QueryFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: success,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)

	if err != nil {
		logger.Error(authErr.Error.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.Redis.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
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
func (s *Service) Signin(ctx context.Context, email, password string) (authModels.ServiceResponse, error) {
	creds, err := s.userrepo.GetUserCreds(ctx, email)
	reqID := request.FromContext(ctx)

	if err != nil || creds == nil {
		logger.Error(authErr.Error.EmailDoesntExist, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    authErr.Error.EmailDoesntExist,
			IsVerified: false,
		}, errors.New(authErr.Error.EmailDoesntExist)
	}

	userId := creds.Id

	isVerified, err := s.userrepo.IsUserVerified(ctx, userId)
	if err != nil {
		logger.Error(dbErr.Error.QueryFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    serverErr.Error.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.Error.InternalError)
	}

	if !authutils.CheckPasswordHash(password, creds.PasswordHash) {
		logger.Warn(authErr.Error.IncorrectPassword, nil, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    authErr.Error.IncorrectPassword,
			IsVerified: false,
		}, errors.New(authErr.Error.IncorrectPassword)
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)
	if err != nil {
		logger.Error(authErr.Error.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success:    false,
			Message:    serverErr.Error.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.Error.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.Redis.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.ServiceResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
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

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (authModels.RefreshTokenServiceResponse, error) {
	reqID := request.FromContext(ctx)

	claims, err := authutils.VerifyAuthToken(refreshToken)
	if err != nil {
		logger.Warn(authErr.Error.InvalidRefreshToken, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(authErr.Error.InvalidRefreshToken)
	}

	userId := claims.UserID
	email := claims.Email
	if userId == "" || email == "" {
		logger.Error("Refresh token missing required claims", nil, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(authErr.Error.InvalidRefreshToken)
	}

	storedToken, err := s.redisrepo.GetRefreshToken(ctx, userId)
	if err != nil || storedToken != refreshToken {
		logger.Warn(authErr.Error.RefreshTokenMismatch, err, logger.Fields{
			"requestId":     reqID,
			"storedToken":   storedToken,
			"providedToken": refreshToken,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(authErr.Error.RefreshTokenMismatch)
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
		logger.Error(authErr.Error.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(serverErr.Error.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, newRefreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.Redis.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenServiceResponse{}, errors.New(serverErr.Error.InternalError)
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

func (s *Service) SignupOTP(ctx context.Context, userId string) (authModels.GenericOTPResponse, error) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "signup",
	}

	success, err := s.otpService.RequestOTP(ctx, userId, "signup")
	if err != nil {
		logger.Error("Failed to send OTP due to service error", err, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: authErr.Error.InternalServiceError,
		}, err
	}

	if !success {
		logger.Warn("OTP service returned unsuccessful result", nil, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: authErr.Error.OTPSendFailure,
		}, nil
	}

	logger.Info("Signup OTP sent successfully", logFields)

	return authModels.GenericOTPResponse{
		Success: true,
		Message: "OTP sent successfully",
	}, nil
}

func (s *Service) SignupOTPVerify(ctx context.Context, userId, otp string) (authModels.GenericOTPResponse, error) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "signup",
	}

	success, err := s.otpService.VerifyOTP(ctx, userId, otp, "signup")
	if err != nil {
		logger.Error("Failed to verify OTP due to service error", err, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: authErr.Error.InternalServiceError,
		}, err
	}

	if !success {
		logger.Warn("OTP verification failed", nil, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: authErr.Error.OTPVerificationFailure,
		}, nil
	}
	err = s.userrepo.MarkUserVerified(ctx, userId)

	if err != nil {
		logger.Warn(dbErr.Error.UpdateFailed, err, logFields)

		return authModels.GenericOTPResponse{
			Success: false,
			Message: "Failed to mark user as verified",
		}, nil
	}

	logger.Info("Signup OTP verified successfully", logFields)

	return authModels.GenericOTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}, nil
}

func (s *Service) ForgotPasswordOTP(ctx context.Context, email string) (authModels.GenericOTPResponse, error) {
	reqID := request.FromContext(ctx)
	creds, err := s.userrepo.GetUserCreds(ctx, email)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warn("Password reset requested for non-existing email", nil, logger.Fields{
				"requestId": reqID,
				"email":     email,
			})
			return authModels.GenericOTPResponse{
				Success: false,
				Message: authErr.Error.EmailDoesntExist,
			}, errors.New(authErr.Error.EmailDoesntExist)
		}
		return authModels.GenericOTPResponse{
			Success: true,
			Message: "OTP sent if password exists",
		}, errors.New(serverErr.Error.InternalError)
	}

	userId := creds.Id
	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}

	success, err := s.otpService.RequestOTP(ctx, userId, "forgot_password")
	if err != nil {
		logger.Error("Failed to send OTP due to service error", err, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: authErr.Error.InternalServiceError,
		}, err
	}

	if !success {
		logger.Warn("OTP service returned unsuccessful result", nil, logFields)
		return authModels.GenericOTPResponse{
			Success: false,
			Message: authErr.Error.OTPSendFailure,
		}, nil
	}

	logger.Info("Forgot Password OTP sent successfully", logFields)

	return authModels.GenericOTPResponse{
		Success: true,
		Message: "OTP sent if password exists",
	}, nil
}

func (s *Service) ForgotPasswordOTPVerify(ctx context.Context, userId string, otp string) (authModels.ForgotPasswordResponse, error) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}

	success, err := s.otpService.VerifyOTP(ctx, userId, otp, "forgot_password")
	if err != nil {
		logger.Error("Failed to verify OTP due to service error", err, logFields)
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: authErr.Error.InternalServiceError,
		}, err
	}

	if !success {
		logger.Warn("OTP verification failed", nil, logFields)
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: authErr.Error.OTPVerificationFailure,
		}, nil
	}

	err = s.redisrepo.SetPasswordResetFlag(ctx, userId, ResetPasswordExpiry)
	if err != nil {
		logger.Warn(dbErr.Redis.SetPasswordResetKeyFailed, err, logFields)
		return authModels.ForgotPasswordResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}

	logger.Info("Forgot Password OTP verified successfully", logFields)

	return authModels.ForgotPasswordResponse{
		Success: true,
		Message: "OTP verified successfully",
		UserId:  userId,
	}, nil
}

func (s *Service) ResetPassword(ctx context.Context, userId string, password string) (authModels.ResetPasswordResponse, error) {
	reqID := request.FromContext(ctx)

	logFields := logger.Fields{
		"userId":    userId,
		"requestId": reqID,
		"purpose":   "forgot_password",
	}
	exists, err := s.userrepo.UserExists(ctx, userId)
	if err != nil {
		logger.Error(dbErr.Error.QueryFailed, err)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}
	if !exists {
		logger.Warn(authErr.Error.UserNotFound, nil, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: authErr.Error.UserNotFound,
		}, errors.New(authErr.Error.UserNotFound)
	}

	isVerified, err := s.redisrepo.CheckPasswordResetFlag(ctx, userId)

	if err != nil {
		logger.Warn(dbErr.Redis.SetPasswordResetKeyFailed, err, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}

	if !isVerified {
		logger.Warn(authErr.Error.PasswordOTPNotVerified, nil, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: authErr.Error.PasswordOTPNotVerified,
		}, errors.New(authErr.Error.PasswordOTPNotVerified)
	}

	err = authModels.ValidatePassword(password)
	if err != nil {
		logger.Warn("Password reset attempt with weak password", nil, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: "Password doesn't match the required criteria",
		}, err
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(authErr.Error.PasswordHashingFailed, err, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}

	err = s.userrepo.ResetPassword(ctx, userId, hash)

	if err != nil {
		logger.Warn(dbErr.Error.UpdateFailed, err, logFields)

		return authModels.ResetPasswordResponse{
			Success: false,
			Message: "Failed to reset password",
		}, nil
	}

	err = s.redisrepo.DeletePasswordResetFlag(ctx, userId)

	if err != nil {
		logger.Warn(dbErr.Redis.SetPasswordResetKeyFailed, err, logFields)
		return authModels.ResetPasswordResponse{
			Success: false,
			Message: serverErr.Error.InternalError,
		}, errors.New(serverErr.Error.InternalError)
	}

	return authModels.ResetPasswordResponse{
		Success: true,
		Message: "Password Reset successfully",
	}, nil
}
