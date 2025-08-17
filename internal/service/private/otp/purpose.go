package otp

type OTPPurpose string

const (
    OTPPurposeSignup         OTPPurpose = "signup"
    OTPPurposeForgotPassword OTPPurpose = "forgot_password"
)

func IsValidPurpose(purpose string) bool {
    switch OTPPurpose(purpose) {
    case OTPPurposeSignup, OTPPurposeForgotPassword:
        return true
    default:
        return false
    }
}