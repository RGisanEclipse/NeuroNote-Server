package auth

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	AccessToken   string `json:"token,omitempty"` // omit when empty (errors)
	RefreshToken string `json:"refreshToken,omitempty"` // omit when empty (errors)
	IsVerified bool `json:"isVerified,omitempty"` // omit when empty (errors)
}
