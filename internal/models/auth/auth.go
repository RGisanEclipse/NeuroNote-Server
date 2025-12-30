package auth

type Request struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string `json:"deviceId"`
}

type ServiceResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	AccessToken  string `json:"token,omitempty"`        // omit when empty (errors)
	RefreshToken string `json:"refreshToken,omitempty"` // omit when empty (errors)
	IsVerified   bool   `json:"isVerified"`
	IsOnboarded  bool   `json:"isOnboarded"`
}
