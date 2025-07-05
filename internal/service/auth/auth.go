package auth

import (
	"context"
	"errors"

	user "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
    "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	authutils "github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

func Signup(ctx context.Context, email, password string) (string, error) {

    hashed, err := authutils.HashPassword(password)
    if err != nil {
        return "", errors.New(auth.AuthError.PasswordHashingFailed)
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
        return "", errors.New(auth.AuthError.TokenGenerationFailed)
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
        return "", errors.New(auth.AuthError.TokenGenerationFailed)
    }
    return token, nil
}