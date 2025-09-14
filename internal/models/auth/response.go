package auth

type Response struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	AccessToken string `json:"token,omitempty"` // omit when empty (errors)
	IsVerified  bool   `json:"isVerified"`
}
