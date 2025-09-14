package auth

type ForgotPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"errorMessage,omitempty"` // omit when empty (errors)
	UserId  string `json:"userId,omitempty"`       // omit when empty (errors)
}
