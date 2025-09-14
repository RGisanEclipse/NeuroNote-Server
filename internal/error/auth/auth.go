package auth

type ErrorMessages struct {
	EmailDoesntExist       string
	EmailExists            string
	IncorrectPassword      string
	InvalidBody            string
	UserIdGenerationFailed string
	PasswordHashingFailed  string
	TokenGenerationFailed  string
	TokenInvalid           string
	Unauthorized           string
	UserNotFound           string
	InvalidRefreshToken    string
	RefreshTokenMismatch   string
	InternalServiceError   string
	OTPSendFailure         string
	OTPVerificationFailure string
	PasswordOTPNotVerified string

	// Email validation errors
	EmailRequired string
	InvalidEmail  string

	// Password validation errors
	PasswordRequired                string
	PasswordTooShort                string
	PasswordTooLong                 string
	PasswordMissingUppercase        string
	PasswordMissingLowercase        string
	PasswordMissingDigit            string
	PasswordMissingSpecialCharacter string
	PasswordContainsWhitespace      string
}

var Error = ErrorMessages{
	EmailDoesntExist:       "email does not exist",
	EmailExists:            "email already exists",
	IncorrectPassword:      "incorrect password",
	InvalidBody:            "invalid request body",
	UserIdGenerationFailed: "user ID generation failed",
	PasswordHashingFailed:  "password hashing failed",
	TokenGenerationFailed:  "token generation failed",
	TokenInvalid:           "invalid token",
	Unauthorized:           "unauthorized access",
	UserNotFound:           "user not found",
	InvalidRefreshToken:    "invalid refresh token",
	RefreshTokenMismatch:   "refresh token does not match stored token",
	InternalServiceError:   "internal service error",
	OTPSendFailure:         "failed to send OTP",
	OTPVerificationFailure: "failed to verify OTP",
	PasswordOTPNotVerified: "password OTP not verified",
	// Email validation messages
	EmailRequired: "email is required",
	InvalidEmail:  "invalid email format",

	// Password validation messages
	PasswordRequired:                "password is required",
	PasswordTooShort:                "password must be at least 8 characters long",
	PasswordTooLong:                 "password must be at most 32 characters long",
	PasswordMissingUppercase:        "password must contain at least one uppercase letter",
	PasswordMissingLowercase:        "password must contain at least one lowercase letter",
	PasswordMissingDigit:            "password must contain at least one digit",
	PasswordMissingSpecialCharacter: "password must contain at least one special character",
	PasswordContainsWhitespace:      "password cannot contain whitespace",
}
