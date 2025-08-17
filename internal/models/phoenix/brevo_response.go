package phoenix

type BrevoResponse struct {
	MessageId string `json:"messageId,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}