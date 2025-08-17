package otp

type OTPErrorMessages struct {
	EmptyEmailForUser    string
	OTPExpiredOrNotFound string
	InvalidOTP           string
}

var OTPError = OTPErrorMessages{
	EmptyEmailForUser:    "email empty for user",
	OTPExpiredOrNotFound: "otp expired or not found",
	InvalidOTP:           "invalid otp",
}