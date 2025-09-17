package otp

type Purpose string

const (
	PurposeSignup         Purpose = "signup"
	PurposeForgotPassword Purpose = "forgot_password"
)

func IsValidPurpose(purpose string) bool {
	switch Purpose(purpose) {
	case PurposeSignup, PurposeForgotPassword:
		return true
	default:
		return false
	}
}
