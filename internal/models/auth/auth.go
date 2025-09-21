package auth

type Request struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Response struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	AccessToken string `json:"token,omitempty"` // omit when empty (errors)
	IsVerified  bool   `json:"isVerified"`
}

type ServiceResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	AccessToken  string `json:"token,omitempty"`        // omit when empty (errors)
	RefreshToken string `json:"refreshToken,omitempty"` // omit when empty (errors)
	IsVerified   bool   `json:"isVerified"`
}
