package auth

type SignupOTPResponse struct {
	Success    bool `json:"success"`
	Message    string `json:"errorMessage,omitempty"` // omit when empty (errors)
}