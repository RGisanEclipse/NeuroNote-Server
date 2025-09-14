package otp

type ErrorMessages struct {
	InvalidOTPRequest    string
	EmptyEmailForUser    string
	OTPExpiredOrNotFound string
	InvalidOTP           string
	InvalidPurpose       string
	OTPCodeMissing       string
}

var Error = ErrorMessages{
	InvalidOTPRequest:    "Invalid otp request",
	EmptyEmailForUser:    "email empty for user",
	OTPExpiredOrNotFound: "otp expired or not found",
	InvalidOTP:           "invalid otp",
	InvalidPurpose:       "invalid purpose",
	OTPCodeMissing:       "code is required",
}
