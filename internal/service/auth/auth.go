package auth

import (
	"context"
	"errors"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	serverErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
    dbErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

type Service struct {
	repo userrepo.Repository
}

func New(repo userrepo.Repository) *Service { return &Service{repo} }

// Signup registers a new user and returns a JWT token.
// It checks if the email is already taken, hashes the password, creates the user
func (s *Service) Signup(ctx context.Context, email, password string) (authModels.AuthResponse, error) {

	exists, err := s.repo.UserExists(ctx, email)
	reqID := request.FromContext(ctx)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err)
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
			IsVerified: false,
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
			IsVerified: false,
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
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	userId, err := s.repo.CreateUser(ctx, email, hash)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}

	token, err := authutils.GenerateToken(userId, email)
	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success: false,
			Message: serverErr.ServerError.InternalError,
			IsVerified: false,
		}, errors.New(serverErr.ServerError.InternalError)
	}
	logger.Info("Account created successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
	})
	return authModels.AuthResponse{
		Success: true,
		Message: "Account created successfully",
		Token:   token,
		IsVerified: true,
	}, nil
}

// Signin authenticates a user and returns a JWT token.
// It checks if the user exists, verifies the password, and generates a token.    
func (s *Service) Signin(ctx context.Context, email, password string) (authModels.AuthResponse, error) {
	creds, err := s.repo.GetUserCreds(ctx, email)
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

	isVerified, err := s.repo.IsUserVerified(ctx, userId)
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
		logger.Warn(authErr.AuthError.IncorrectPassword, err, logger.Fields{
			"requestId": reqID,
		})
		return authModels.AuthResponse{
			Success:    false,
			Message:    authErr.AuthError.IncorrectPassword,
			IsVerified: false,
		}, errors.New(authErr.AuthError.IncorrectPassword)
	}

	token, err := authutils.GenerateToken(userId, email)
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
	logger.Info("User logged in successfully", logger.Fields{
		"email":     email,
		"requestId": reqID,
	})
	return authModels.AuthResponse{
		Success:    true,
		Message:    "Logged in successfully",
		Token:      token,
		IsVerified: isVerified,
	}, nil
}