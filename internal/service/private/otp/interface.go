package otp

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/otp"
)

type OTPService interface {
	RequestOTP(ctx context.Context, userID string, purpose string) (*otp.OTPResponse, error)
	VerifyOTP(ctx context.Context, userID string, code string, purpose string) (*otp.OTPResponse, error)
}