package auth

import (
	"context"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	redisrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	userrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	authModels "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	otpService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
)

// Service is the concrete implementation that powers all auth flows.
// It implements SigninService, SignupService, PasswordResetService, and TokenService.

type Service struct {
	Signin         SigninService
	Signup         SignupService
	ForgotPassword ForgotPasswordService
}

func NewService(
	userRepo userrepo.Repository,
	redisRepo redisrepo.Repository,
	otpSvc otpService.S,
) *Service {
	return &Service{
		Signin:         NewSigninService(userRepo, redisRepo),
		Signup:         NewSignupService(userRepo, otpSvc, redisRepo),
		ForgotPassword: NewForgotPasswordService(userRepo, otpSvc, redisRepo),
	}
}

const (
	RefreshTokenExpiry  = 7 * 24 * time.Hour
	ResetPasswordExpiry = 10 * time.Minute
)

type signupService struct {
	userRepo   userrepo.Repository
	otpService otpService.S
	redisRepo  redisrepo.Repository
}

type signinService struct {
	userRepo  userrepo.Repository
	redisRepo redisrepo.Repository
}

type forgotPasswordService struct {
	userRepo   userrepo.Repository
	otpService otpService.S
	redisRepo  redisrepo.Repository
}

func NewSignupService(userRepo userrepo.Repository, otpSvc otpService.S, redisRepo redisrepo.Repository) SignupService {
	return &signupService{userRepo: userRepo, otpService: otpSvc, redisRepo: redisRepo}
}

func NewSigninService(userRepo userrepo.Repository, redisRepo redisrepo.Repository) SigninService {
	return &signinService{userRepo: userRepo, redisRepo: redisRepo}
}

func NewForgotPasswordService(userRepo userrepo.Repository, otpSvc otpService.S, redisRepo redisrepo.Repository) ForgotPasswordService {
	return &forgotPasswordService{userRepo: userRepo, otpService: otpSvc, redisRepo: redisRepo}
}

type SigninService interface {
	Signin(ctx context.Context, email, password string) (authModels.ServiceResponse, *appError.Code)
	RefreshToken(ctx context.Context, refreshToken string) (authModels.RefreshTokenServiceResponse, *appError.Code)
}

type SignupService interface {
	Signup(ctx context.Context, email, password string) (authModels.ServiceResponse, *appError.Code)
	SignupOTP(ctx context.Context, userId string) (authModels.GenericOTPResponse, *appError.Code)
	SignupOTPVerify(ctx context.Context, userId, code string) (authModels.GenericOTPResponse, *appError.Code)
}

type ForgotPasswordService interface {
	ForgotPasswordOTP(ctx context.Context, email string) (authModels.ForgotPasswordOTPResponse, *appError.Code)
	ForgotPasswordOTPVerify(ctx context.Context, userId, code string) (authModels.ForgotPasswordResponse, *appError.Code)
	ResetPassword(ctx context.Context, userId, password string) (authModels.ResetPasswordResponse, *appError.Code)
}
