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
)

type Service struct {
	userrepo userrepo.Repository
	redisrepo redisrepo.Repository
}

const RefreshTokenExpiry = 7 * 24 * time.Hour

func New(userrepo userrepo.Repository, redisrepo redisrepo.Repository) *Service { return &Service{userrepo, redisrepo} }

// Signup registers a new user and returns a JWT token.
// It checks if the email is already taken, hashes the password, creates the user
func (s *Service) Signup(ctx context.Context, email, password string) (authModels.AuthResponse, error) {

	exists, err := s.userrepo.UserExists(ctx, email)
	reqID := request.FromContext(ctx)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err)
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}
	if exists {
        logger.Info(authErr.AuthError.EmailExists, logger.Fields{
			"email":     email,
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success: false,
			Message: authErr.AuthError.EmailExists,
		}, errors.New(authErr.AuthError.EmailExists)
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(authErr.AuthError.PasswordHashingFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
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
		return authModels.AuthResponse{
			Success: success,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	accessToken, refreshToken, err := authutils.GenerateTokenPair(userId, email)

	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}
	
	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.RedisError.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	logger.Info("Account created successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
		"userId":    userId,
	})
	return authModels.AuthResponse{
		Success: true,
		Message: "Account created successfully",
		AccessToken:   accessToken,
		RefreshToken: refreshToken,
		IsVerified: false,
	}, nil
}

// Signin authenticates a user and returns a JWT token.
// It checks if the user exists, verifies the password, and generates a token.    
func (s *Service) Signin(ctx context.Context, email, password string) (authModels.AuthResponse, error) {
	creds, err := s.userrepo.GetUserCreds(ctx, email)
	reqID := request.FromContext(ctx)

	if err != nil || creds == nil {
		logger.Error(authErr.AuthError.EmailDoesntExist, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
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
		return authModels.AuthResponse{
			Success:    false,
			Message:    serverErr.ServerError.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	if !authutils.CheckPasswordHash(password, creds.PasswordHash) {
		logger.Warn(authErr.AuthError.IncorrectPassword, nil, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
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
		return authModels.AuthResponse{
			Success:    false,
			Message:    serverErr.ServerError.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, refreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.RedisError.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	logger.Info("User logged in successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
		"userId":    userId,
	})
	return authModels.AuthResponse{
		Success:    true,
		Message:    "Logged in successfully",
		AccessToken: accessToken,
		RefreshToken: refreshToken,
		IsVerified: isVerified,
	}, nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (authModels.RefreshTokenResponse, error) {
	reqID := request.FromContext(ctx)

	claims, err := authutils.VerifyAuthToken(refreshToken)
	if err != nil {
		logger.Warn(authErr.AuthError.InvalidRefreshToken, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenResponse{}, errors.New(authErr.AuthError.InvalidRefreshToken)
	}

	userId := claims.UserID
	email := claims.Email
	if userId == "" || email == "" {
		logger.Error("Refresh token missing required claims", nil, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenResponse{}, errors.New(authErr.AuthError.InvalidRefreshToken)
	}

	storedToken, err := s.redisrepo.GetRefreshToken(ctx, userId)
	if err != nil || storedToken != refreshToken {
		logger.Warn(authErr.AuthError.RefreshTokenMismatch, err, logger.Fields{
			"requestId":    reqID,
			"storedToken":  storedToken,
			"providedToken": refreshToken,
		})
		return authModels.RefreshTokenResponse{}, errors.New(authErr.AuthError.RefreshTokenMismatch)
	}

	// Immediately delete the used refresh token to prevent reuse
	if err := s.redisrepo.DeleteRefreshToken(ctx, userId); err != nil {
		logger.Error("Failed to delete used refresh token", err, logger.Fields{
			"requestId": reqID,
			"userId":    userId,
		})
		// Don't fail the request if we can't delete the token, just log it
		// The token will eventually expire anyway
	}

	newAccessToken, newRefreshToken, err := authutils.GenerateTokenPair(userId, email)
	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenResponse{}, errors.New(serverErr.ServerError.InternalError)
	}

	if err := s.redisrepo.SetRefreshToken(ctx, userId, newRefreshToken, RefreshTokenExpiry); err != nil {
		logger.Error(dbErr.RedisError.SetRefreshTokenFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.RefreshTokenResponse{}, errors.New(serverErr.ServerError.InternalError)
	}

	logger.Info("Refresh token generated successfully", logger.Fields{
		"requestId": reqID,
		"userId":    userId,
		"oldTokenExpiry": claims.ExpiresAt.Time,
	})
	
	return authModels.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}