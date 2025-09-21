package otp

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
)

type S interface {
	RequestOTP(ctx context.Context, userID string, purpose string) (bool, *appError.Code, error)
	VerifyOTP(ctx context.Context, userID string, code string, purpose string) (bool, *appError.Code, error)
}
