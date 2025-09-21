package auth

type SignupOTPRequest struct {
	UserId string `json:"userId"`
}

type ForgotPasswordOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type OTPVerifyRequest struct {
	UserId string `json:"userId"`
	Code   string `json:"code"`
}

type GenericOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"errorMessage,omitempty"` // omit when empty (errors)
}

type ForgotPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"errorMessage,omitempty"` // omit when empty (errors)
	UserId  string `json:"userId,omitempty"`       // omit when empty (errors)
}
