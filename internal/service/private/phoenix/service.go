package phoenix

import (
	"context"

	"github.com/RGisanEclipse/AVYO-Server/internal/db/user"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/phoenix"
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
