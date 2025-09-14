package auth

type ResetPasswordRequest struct {
	UserId   string `json:"userId"`
	Password string `json:"password"`
}
