package auth

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
)

type S interface {
	Signup(ctx context.Context, email, password string) (auth.ServiceResponse, *appError.Code)
	Signin(ctx context.Context, email, password string) (auth.ServiceResponse, *appError.Code)
	SignupOTP(ctx context.Context, userId string) (auth.GenericOTPResponse, *appError.Code)
	SignupOTPVerify(ctx context.Context, userId, code string) (auth.GenericOTPResponse, *appError.Code)
	ForgotPasswordOTP(ctx context.Context, email string) (auth.GenericOTPResponse, *appError.Code)
	ForgotPasswordOTPVerify(ctx context.Context, userId, code string) (auth.ForgotPasswordResponse, *appError.Code)
	ResetPassword(ctx context.Context, userId, password string) (auth.ResetPasswordResponse, *appError.Code)
	RefreshToken(ctx context.Context, refreshToken string) (auth.RefreshTokenServiceResponse, *appError.Code)
}
