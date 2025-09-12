package auth

type SignupOTPVerifyRequest struct {
	UserId string `json:"userId"`
	Code   string `json:"code"`
}