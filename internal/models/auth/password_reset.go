package auth

type ResetPasswordRequest struct {
	UserId   string `json:"userId"`
	Password string `json:"password"`
}

type ResetPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"errorMessage,omitempty"` // omit when empty (errors)
}
