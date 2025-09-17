package otp

type Request struct {
	Purpose string `json:"purpose"`
}

type VerifyRequest struct {
	OTP     string `json:"otp"`
	Purpose string `json:"purpose"`
}
