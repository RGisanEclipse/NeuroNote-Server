package auth

type SignupOTPRequest struct {
	UserId string `json:"userId"`
}

type ForgotPasswordOTPRequest struct {
	Email string `json:"email"`
}

type ForgotPasswordOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	UserId  string `json:"userId"`
}

type OTPVerifyRequest struct {
	UserId string `json:"userId"`
	Code   string `json:"code"`
}

type GenericOTPResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type ForgotPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	UserId  string `json:"userId,omitempty"` // omit when empty (errors)
}
