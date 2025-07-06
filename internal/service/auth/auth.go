package auth

import (
	"context"
	"errors"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	serverErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
    dbErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

type Service struct {
	repo userrepo.Repository
}

func New(repo userrepo.Repository) *Service { return &Service{repo} }

// Signup registers a new user and returns a JWT token.
// It checks if the email is already taken, hashes the password, creates the user
func (s *Service) Signup(ctx context.Context, email, password string) (string, error) {

	exists, err := s.repo.UserExists(ctx, email)
	if err != nil {
		logger.Error(dbErr.DBError.QueryFailed, err)
		return "", err
	}
	if exists {
        logger.Error(authErr.AuthError.EmailExists, nil)
		return "", errors.New(authErr.AuthError.EmailExists)
	}

	hash, err := authutils.HashPassword(password)
	if err != nil {
		logger.Error(authErr.AuthError.PasswordHashingFailed, err)
		return "", errors.New(serverErr.ServerError.InternalError)
	}

	userID, err := s.repo.CreateUser(ctx, email, hash)
	if err != nil {
        logger.Error(dbErr.DBError.QueryFailed, err)
		return "", err 
	}

	token, err := authutils.GenerateToken(userID, email)
	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err)
		return "", errors.New(serverErr.ServerError.InternalError)
	}
	return token, nil
}

// Signin authenticates a user and returns a JWT token.
// It checks if the user exists, verifies the password, and generates a token.    
func (s *Service) Signin(ctx context.Context, email, password string) (string, error) {
	creds, err := s.repo.GetUserCreds(ctx, email)
	if err != nil {
		return "", errors.New(authErr.AuthError.EmailDoesntExist)
	}

	if !authutils.CheckPasswordHash(password, creds.PasswordHash) {
		return "", errors.New(authErr.AuthError.IncorrectPassword)
	}

	token, err := authutils.GenerateToken(creds.ID, email)
	if err != nil {
		logger.Error(authErr.AuthError.TokenGenerationFailed, err)
		return "", errors.New(serverErr.ServerError.InternalError)
	}
	return token, nil
}