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
}