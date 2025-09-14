package auth

type OTPVerifyRequest struct {
	UserId string `json:"userId"`
	Code   string `json:"code"`
}
