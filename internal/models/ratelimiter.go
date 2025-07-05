package models

type RateLimitResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}