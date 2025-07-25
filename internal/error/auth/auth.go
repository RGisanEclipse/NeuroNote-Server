package auth

type AuthErrorMessages struct {
	EmailDoesntExist       string
	EmailExists            string
	IncorrectPassword      string
	InvalidBody            string
	PasswordHashingFailed  string
	TokenGenerationFailed  string
	TokenInvalid           string
	Unauthorized           string
	UserNotFound           string

	// Email validation errors
	EmailRequired                     string
	InvalidEmail                      string

	// Password validation errors
	PasswordRequired                  string
	PasswordTooShort                  string
	PasswordTooLong                   string
	PasswordMissingUppercase          string
	PasswordMissingLowercase          string
	PasswordMissingDigit              string
	PasswordMissingSpecialCharacter   string
	PasswordContainsWhitespace        string
}

var AuthError = AuthErrorMessages{
	EmailDoesntExist:       "email does not exist",
	EmailExists:            "email already exists",
	IncorrectPassword:      "incorrect password",
	InvalidBody:            "invalid request body",
	PasswordHashingFailed:  "password hashing failed",
	TokenGenerationFailed:  "token generation failed",
	TokenInvalid:           "invalid token",
	Unauthorized:           "unauthorized access",
	UserNotFound:           "user not found",
	
	// Email validation messages
	EmailRequired:                     "email is required",
	InvalidEmail:                      "invalid email format",

	// Password validation messages
	PasswordRequired:                  "password is required",
	PasswordTooShort:                  "password must be at least 8 characters long",
	PasswordTooLong:                   "password must be at most 32 characters long",
	PasswordMissingUppercase:          "password must contain at least one uppercase letter",
	PasswordMissingLowercase:          "password must contain at least one lowercase letter",
	PasswordMissingDigit:              "password must contain at least one digit",
	PasswordMissingSpecialCharacter:   "password must contain at least one special character",
	PasswordContainsWhitespace:        "password cannot contain whitespace",
}