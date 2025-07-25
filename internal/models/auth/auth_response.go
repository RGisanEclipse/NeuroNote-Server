package auth

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"` // omit when empty (errors)
	IsVerified bool `json:"isVerified"`
}
