package phoenix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/phoenix"
	"github.com/sirupsen/logrus"
)

type BrevoClient struct {
	APIKey string
	Client *http.Client
}

func NewBrevoClient() *BrevoClient {
	return &BrevoClient{
		APIKey: os.Getenv("BREVO_API_KEY"),
		Client: &http.Client{},
	}
}

var baseURL = "https://api.brevo.com/v3/smtp/email"

func (c *BrevoClient) SendEmail(ctx context.Context, request phoenix.BrevoRequest) (phoenix.Response, error) {
	bodyBytes, err := json.Marshal(request)
	if err != nil {
		logger.Error("Failed to marshal JSON", err, appError.ServerJSONMarshalError)
		return phoenix.Response{
			Success: false,
			Error:   appError.ServerJSONMarshalError.Message,
		}, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.Error("Failed to create request", err, appError.ServerRequestCreationFailure)
		return phoenix.Response{
			Success: false,
			Error:   appError.ServerRequestCreationFailure.Message,
		}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		logger.Error("Failed to send request", err, appError.ServerRequestDeliveryFailure)
		return phoenix.Response{
			Success: false,
			Error:   appError.ServerRequestDeliveryFailure.Message,
		}, err
	}
	defer resp.Body.Close()

	var brevoResponse phoenix.BrevoResponse
	if err := json.NewDecoder(resp.Body).Decode(&brevoResponse); err != nil {
		logger.Error("Failed to unmarshal JSON", err, appError.ServerJSONUnmarshalError)
		return phoenix.Response{
			Success: false,
			Error:   appError.ServerJSONUnmarshalError.Message,
		}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Received non-200 response", errors.New(brevoResponse.Message), appError.ServerNon200ResponseError)
		return phoenix.Response{
			Success: false,
			Error:   brevoResponse.Message,
		}, errors.New(brevoResponse.Message)
	}
	logger.Info("Email sent successfully", logrus.Fields{
		"messageId": brevoResponse.MessageId,
	})
	return phoenix.Response{
		Success:   true,
		MessageId: brevoResponse.MessageId,
	}, nil
}
