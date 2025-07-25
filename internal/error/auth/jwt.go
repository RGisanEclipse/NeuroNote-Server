package auth

type JWTErrorMessages struct {
	JWTSecretNotSet           string
	TokenGenerationFailed     string
	TokenInvalid              string
	TokenExpired              string
	InvalidTokenSigningMethod string
}

var JWTError = JWTErrorMessages{
	JWTSecretNotSet:		  "JWT_SECRET environment variable is not set",
	TokenGenerationFailed:    "failed to generate token",
	TokenInvalid:             "invalid token",
	TokenExpired:             "token has expired",
	InvalidTokenSigningMethod: "invalid token signing method",
}