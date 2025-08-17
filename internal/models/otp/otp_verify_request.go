package otp

type OTPVerifyRequest struct {
	OTP string `json:"otp"`
	Purpose string `json:"purpose"`
}