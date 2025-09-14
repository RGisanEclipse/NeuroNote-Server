package otp

type VerifyRequest struct {
	OTP     string `json:"otp"`
	Purpose string `json:"purpose"`
}
