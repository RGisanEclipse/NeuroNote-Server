package phoenix

import (
	"context"
	"errors"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	dbErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	phoenixErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/phoenix"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
	"github.com/sirupsen/logrus"
)

type Service struct {
	userrepo user.Repository
	client   *BrevoClient
}

func New(userrepo user.Repository, client *BrevoClient) *Service {
	return &Service{
		userrepo: userrepo,
		client:   client,
	}
}

func (s *Service) SendMail(ctx context.Context, userId string, template phoenix.EmailTemplate) error {
	requestId := request.FromContext(ctx)
	email, err := s.userrepo.GetUserEmailById(ctx, userId)
	if err != nil {
		logger.Error(dbErr.Error.EmailQueryFailed, err, logger.Fields{
			"userId":    userId,
			"requestId": requestId,
		})
		return errors.New(dbErr.Error.EmailQueryFailed)
	}

	response, err := s.client.SendEmail(
		ctx,
		phoenix.BrevoRequest{
			Sender: phoenix.BrevoContact{
				Email: "rishab28guleria@gmail.com",
			},
			To: []phoenix.BrevoContact{
				{
					Email: email,
				},
			},
			Subject:     template.Subject,
			HTMLContent: template.BodyHTML,
		},
	)
	if err != nil {
		logger.Error(phoenixErr.ErrorMessages.EmailDeliveryFailed, err, logrus.Fields{
			"userId":       userId,
			"requestId":    requestId,
			"errorMessage": err.Error(),
		})
		return errors.New(phoenixErr.ErrorMessages.EmailDeliveryFailed)
	}
	if !response.Success {
		logger.Error(phoenixErr.ErrorMessages.EmailDeliveryFailed, nil, logrus.Fields{
			"userId":       userId,
			"requestId":    requestId,
			"errorMessage": response.Message,
		})
		return errors.New(phoenixErr.ErrorMessages.EmailDeliveryFailed)
	}

	logger.Info("Email sent successfully", logrus.Fields{
		"userId":    userId,
		"requestId": requestId,
	})

	return nil
}
