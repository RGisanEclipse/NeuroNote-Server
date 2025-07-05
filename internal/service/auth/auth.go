package auth

import (
	"context"
	"errors"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	user "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

func Signup(ctx context.Context, email, password string) (string, error) {

    hashed, err := authutils.HashPassword(password)
    if err != nil {
        logger.Error(auth.AuthError.PasswordHashingFailed, err)
        return "", errors.New(server.ServerError.InternalError)
    }

    // Check if email already exists
    _, _, err = user.GetUserCreds(ctx, email)
    if err == nil {
        return "", errors.New(auth.AuthError.EmailExists)
    }

    userID, err := user.CreateUser(ctx, email, hashed)
    if err != nil {
        return "", err
    }

    token, err := authutils.GenerateToken(userID, email)
    if err != nil {
        logger.Error(auth.AuthError.TokenGenerationFailed, err)
        return "", errors.New(server.ServerError.InternalError)
    }
    return token, nil
}

func Signin(ctx context.Context, email, password string) (string, error) {
    userID, hash, err := user.GetUserCreds(ctx, email)
    if err != nil {
        return "", errors.New(auth.AuthError.EmailDoesntExist)
    }
    if !authutils.CheckPasswordHash(password, hash) {
        return "", errors.New(auth.AuthError.IncorrectPassword)
    }
    token, err := authutils.GenerateToken(userID, email)
    if err != nil {
        logger.Error(auth.AuthError.TokenGenerationFailed, err)
        return "", errors.New(server.ServerError.InternalError)
    }
    return token, nil
}