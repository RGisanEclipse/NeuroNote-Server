package phoenix

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
)

type Service interface {
	SendMail(ctx context.Context, userId string, template phoenix.EmailTemplate) error
}

type MailService struct {
	userRepo user.Repository
	client   *BrevoClient
}

func New(userrepo user.Repository, client *BrevoClient) *MailService {
	return &MailService{
		userRepo: userrepo,
		client:   client,
	}
}
