package phoenix

import (
	"context"
	"errors"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
	"github.com/sirupsen/logrus"
)

func (s *MailService) SendMail(ctx context.Context, userId string, template phoenix.EmailTemplate) error {
	requestId := request.FromContext(ctx)
	email, err := s.userRepo.GetUserEmailById(ctx, userId)
	if err != nil {
		logger.Error("Failed to get user email", err, appError.DBEmailQueryFailed, logger.Fields{
			"userId":    userId,
			"requestId": requestId,
		})
		return appError.DBEmailQueryFailed
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
		logger.Error("Failed to send email", err, appError.PhoenixEmailDeliveryFailed, logrus.Fields{
			"userId":       userId,
			"requestId":    requestId,
			"errorMessage": err.Error(),
		})
		return appError.PhoenixEmailDeliveryFailed
	}
	if !response.Success {
		logger.Error("Email delivery failed", errors.New(response.Error), appError.PhoenixEmailDeliveryFailed, logrus.Fields{
			"userId":       userId,
			"requestId":    requestId,
			"errorMessage": response.Error,
		})
		return appError.PhoenixEmailDeliveryFailed
	}

	logger.Info("Email sent successfully", logrus.Fields{
		"userId":    userId,
		"requestId": requestId,
	})

	return nil
}
