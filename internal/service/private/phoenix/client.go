package phoenix

import (
	"bytes"
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

func (c *BrevoClient) SendEmail(request phoenix.BrevoRequest) (phoenix.PhoenixResponse, error) {
	bodyBytes, err := json.Marshal(request)
	if err != nil {
		logger.Error(serverErr.ServerError.JSONMarshalError, err)
		return phoenix.PhoenixResponse{
			Success: false,
			Error:   serverErr.ServerError.JSONMarshalError,
		}, err
	}

	req, err := http.NewRequest("POST", baseURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.Error(serverErr.ServerError.RequestCreationFailure, err)
		return phoenix.PhoenixResponse{
			Success: false,
			Error:   serverErr.ServerError.RequestCreationFailure,
		}, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", c.APIKey)

	resp, err := c.Client.Do(req)
	if err != nil {
		logger.Error(serverErr.ServerError.RequestDeliveryFailure, err)
		return phoenix.PhoenixResponse{
			Success: false,
			Error:   serverErr.ServerError.RequestDeliveryFailure,
		}, err
	}
	defer resp.Body.Close()

	var brevoResponse phoenix.BrevoResponse
	if err := json.NewDecoder(resp.Body).Decode(&brevoResponse); err != nil {
		logger.Error(serverErr.ServerError.JSONUnmarshalError, err)
		return phoenix.PhoenixResponse{
			Success: false,
			Error:   serverErr.ServerError.JSONUnmarshalError,
		}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error(serverErr.ServerError.Non200ResponseError, nil)
		return phoenix.PhoenixResponse{
			Success: false,
			Error:   brevoResponse.Message,
		}, errors.New(brevoResponse.Message)
	}
	logger.Info("Email sent successfully", logrus.Fields{
		"messageId": brevoResponse.MessageId,
	})
	return phoenix.PhoenixResponse{
		Success:   true,
		MessageId: brevoResponse.MessageId,
	}, nil
}