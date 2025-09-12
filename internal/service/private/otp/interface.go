package otp

import (
	"context"
)

type OTPService interface {
	RequestOTP(ctx context.Context, userID string, purpose string) (bool, error)
	VerifyOTP(ctx context.Context, userID string, code string, purpose string) (bool, error)
}