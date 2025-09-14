package phoenix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	serverErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
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
		logger.Error(serverErr.Error.JSONMarshalError, err)
		return phoenix.Response{
			Success: false,
			Error:   serverErr.Error.JSONMarshalError,
		}, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.Error(serverErr.Error.RequestCreationFailure, err)
		return phoenix.Response{
			Success: false,
			Error:   serverErr.Error.RequestCreationFailure,
		}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		logger.Error(serverErr.Error.RequestDeliveryFailure, err)
		return phoenix.Response{
			Success: false,
			Error:   serverErr.Error.RequestDeliveryFailure,
		}, err
	}
	defer resp.Body.Close()

	var brevoResponse phoenix.BrevoResponse
	if err := json.NewDecoder(resp.Body).Decode(&brevoResponse); err != nil {
		logger.Error(serverErr.Error.JSONUnmarshalError, err)
		return phoenix.Response{
			Success: false,
			Error:   serverErr.Error.JSONUnmarshalError,
		}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error(serverErr.Error.Non200ResponseError, nil)
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
