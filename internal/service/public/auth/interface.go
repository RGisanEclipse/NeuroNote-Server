// internal/service/auth/service.go
package auth

import (
	"context"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

type AuthService interface {
	Signup(ctx context.Context, email, password string) (auth.AuthResponse, error)
	Signin(ctx context.Context, email, password string) (auth.AuthResponse, error)
	RefreshToken (ctx context.Context, refreshToken string) (auth.RefreshTokenResponse, error)
}