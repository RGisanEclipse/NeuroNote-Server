package auth

type ForgotPasswordOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}
