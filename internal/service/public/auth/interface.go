package auth

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

type AuthService interface {
	Signup (ctx context.Context, email, password string) (auth.AuthServiceResponse, error)
	Signin (ctx context.Context, email, password string) (auth.AuthServiceResponse, error)
	SignupOTP (ctx context.Context, userId string) (auth.SignupOTPResponse, error)
	SignupOTPVerify (ctx context.Context, userId, code string) (auth.SignupOTPResponse, error)
	RefreshToken (ctx context.Context, refreshToken string) (auth.RefreshTokenServiceResponse, error)
}