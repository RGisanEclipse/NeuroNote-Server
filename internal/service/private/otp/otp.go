package otp

import (
	"context"

	models "github.com/RGisanEclipse/NeuroNote-Server/internal/models/otp"
	redisrepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
)

type otpService struct {
	repo redisrepo.Repository
}

func New(repo redisrepo.Repository) OTPService {
	return &otpService{repo: repo}
}

func (s *otpService) RequestOTP(ctx context.Context, userID string) (*models.OTPResponse, error) {
	// Generate & store OTP in Redis, send to email/phone etc.
	return &models.OTPResponse{
		Success: true,
		Message: "OTP sent successfully",
	}, nil
}

func (s *otpService) VerifyOTP(ctx context.Context, userID string, code string) (*models.OTPResponse, error) {
	// Verify OTP logic (compare with Redis, etc.)
	return &models.OTPResponse{
		Success: true,
		Message: "OTP verified",
	}, nil
}