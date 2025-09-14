package auth

// ServiceResponse is Internal Service Response
type ServiceResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	AccessToken  string `json:"token,omitempty"`        // omit when empty (errors)
	RefreshToken string `json:"refreshToken,omitempty"` // omit when empty (errors)
	IsVerified   bool   `json:"isVerified"`
}
