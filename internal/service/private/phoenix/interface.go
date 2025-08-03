package phoenix

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
)

type PhoenixService interface {
	SendMail(ctx context.Context, userID string) (*phoenix.EmailTemplate, error)
}