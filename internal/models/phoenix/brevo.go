package phoenix

type BrevoRequest struct {
	Sender      BrevoContact   `json:"sender"`
	To          []BrevoContact `json:"to"`
	Subject     string         `json:"subject"`
	HTMLContent string         `json:"htmlContent"`
}

type BrevoContact struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type BrevoResponse struct {
	MessageId string `json:"messageId,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}
