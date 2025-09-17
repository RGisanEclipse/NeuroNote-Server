package auth

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

type S interface {
	Signup(ctx context.Context, email, password string) (auth.ServiceResponse, error)
	Signin(ctx context.Context, email, password string) (auth.ServiceResponse, error)
	SignupOTP(ctx context.Context, userId string) (auth.GenericOTPResponse, error)
	SignupOTPVerify(ctx context.Context, userId, code string) (auth.GenericOTPResponse, error)
	ForgotPasswordOTP(ctx context.Context, email string) (auth.GenericOTPResponse, error)
	ForgotPasswordOTPVerify(ctx context.Context, userId, code string) (auth.ForgotPasswordResponse, error)
	ResetPassword(ctx context.Context, userId, password string) (auth.ResetPasswordResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (auth.RefreshTokenServiceResponse, error)
}
