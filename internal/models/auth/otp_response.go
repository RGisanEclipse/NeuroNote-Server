package auth

type OTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"errorMessage,omitempty"` // omit when empty (errors)
}
