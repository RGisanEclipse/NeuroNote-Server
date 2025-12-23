package error

import (
	"net/http"
)

// Code represents a structured error with code, message, and HTTP status
type Code struct {
	Code    string
	Message string
	Status  int
}

// Error implements the error interface
func (e *Code) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// NewErrorCode creates a new ErrorCode instance
func NewErrorCode(code, message string, status int) *Code {
	return &Code{
		Code:    code,
		Message: message,
		Status:  status,
	}
}

//
// Error codes by category (camelCase, Go convention)
//

// Authentication errors (auth*)
const (
	authEmailDoesntExist          = "AUTH_001"
	authEmailExists               = "AUTH_002"
	authIncorrectPassword         = "AUTH_003"
	authInvalidBody               = "AUTH_004"
	authUserIDGenerationFailed    = "AUTH_005"
	authPasswordHashingFailed     = "AUTH_006"
	authTokenGenerationFailed     = "AUTH_007"
	authTokenInvalid              = "AUTH_008"
	authUnauthorized              = "AUTH_009"
	authUserNotFound              = "AUTH_010"
	authInvalidRefreshToken       = "AUTH_011"
	authRefreshTokenMismatch      = "AUTH_012"
	authInternalServiceError      = "AUTH_013"
	authOtpSendFailure            = "AUTH_014"
	authOtpVerificationFailure    = "AUTH_015"
	authPasswordOtpNotVerified    = "AUTH_016"
	authSignupFailed              = "AUTH_017"
	authSigninFailed              = "AUTH_018"
	authTokenVerificationFailed   = "AUTH_019"
	authInvalidTokenSigningMethod = "AUTH_020"
	authUserNotVerified           = "AUTH_021"
)

// Email validation errors (email*)
const (
	emailRequired = "EMAIL_001"
	emailInvalid  = "EMAIL_002"
)

// Password validation errors (password*)
const (
	passwordRequired           = "PASSWORD_001"
	passwordTooShort           = "PASSWORD_002"
	passwordTooLong            = "PASSWORD_003"
	passwordMissingUppercase   = "PASSWORD_004"
	passwordMissingLowercase   = "PASSWORD_005"
	passwordMissingDigit       = "PASSWORD_006"
	passwordMissingSpecialChar = "PASSWORD_007"
	passwordContainsWhitespace = "PASSWORD_008"
)

// Database errors (db*)
const (
	dbConnectionFailed   = "DB_001"
	dbQueryFailed        = "DB_002"
	dbInsertFailed       = "DB_003"
	dbUpdateFailed       = "DB_004"
	dbUserCreationFailed = "DB_005"
	dbUserQueryFailed    = "DB_006"
	dbEmailQueryFailed   = "DB_007"
)

// Onboarding errors (ob*)
const (
	obNameTooLong          = "OB_001"
	obNameTooShort         = "OB_002"
	obInvalidAge           = "OB_003"
	obInvalidGender        = "OB_004"
	obUserAlreadyOnboarded = "OB_005"
)

// Redis errors (redis*)
const (
	redisConnectionFailed             = "REDIS_001"
	redisSetRefreshTokenFailed        = "REDIS_002"
	redisGetRefreshTokenFailed        = "REDIS_003"
	redisDeleteRefreshTokenFailed     = "REDIS_004"
	redisGetOtpFailed                 = "REDIS_005"
	redisSetPasswordResetKeyFailed    = "REDIS_006"
	redisDeletePasswordResetKeyFailed = "REDIS_007"
	redisDeleteOTPFailed              = "REDIS_008"
	redisSetOtpFailed                 = "REDIS_009"
)

// OTP errors (otp*)
const (
	otpInvalidRequest    = "OTP_001"
	otpEmptyEmailForUser = "OTP_002"
	otpExpiredOrNotFound = "OTP_003"
	otpInvalid           = "OTP_004"
	otpInvalidPurpose    = "OTP_005"
	otpCodeMissing       = "OTP_006"
)

// Phoenix/Email service errors (phoenix*)
const (
	phoenixEmailDeliveryFailed = "PHOENIX_001"
)

// Server errors (server*)
const (
	serverMissingEnvVars         = "SERVER_001"
	serverStartupFailed          = "SERVER_002"
	serverShutdownFailed         = "SERVER_003"
	serverInternalError          = "SERVER_004"
	serverInvalidBody            = "SERVER_005"
	serverTooManyRequests        = "SERVER_006"
	serverHTTPServerError        = "SERVER_007"
	serverBadRequest             = "SERVER_008"
	serverUnauthorized           = "SERVER_009"
	serverJSONMarshalError       = "SERVER_010"
	serverJSONUnmarshalError     = "SERVER_011"
	serverRequestCreationFailure = "SERVER_012"
	serverRequestDeliveryFailure = "SERVER_013"
	serverNon200ResponseError    = "SERVER_014"
)

// Error definitions with codes, messages, and HTTP status codes
var (
	AuthEmailDoesntExist          = NewErrorCode(authEmailDoesntExist, "email does not exist", http.StatusNotFound)
	AuthEmailExists               = NewErrorCode(authEmailExists, "email already exists", http.StatusConflict)
	AuthIncorrectPassword         = NewErrorCode(authIncorrectPassword, "incorrect password", http.StatusUnauthorized)
	AuthInvalidBody               = NewErrorCode(authInvalidBody, "invalid request body", http.StatusBadRequest)
	AuthUserIDGenerationFailed    = NewErrorCode(authUserIDGenerationFailed, "user ID generation failed", http.StatusInternalServerError)
	AuthPasswordHashingFailed     = NewErrorCode(authPasswordHashingFailed, "password hashing failed", http.StatusInternalServerError)
	AuthTokenGenerationFailed     = NewErrorCode(authTokenGenerationFailed, "token generation failed", http.StatusInternalServerError)
	AuthTokenInvalid              = NewErrorCode(authTokenInvalid, "invalid token", http.StatusUnauthorized)
	AuthUnauthorized              = NewErrorCode(authUnauthorized, "unauthorized access", http.StatusUnauthorized)
	AuthUserNotFound              = NewErrorCode(authUserNotFound, "user not found", http.StatusNotFound)
	AuthInvalidRefreshToken       = NewErrorCode(authInvalidRefreshToken, "invalid refresh token", http.StatusUnauthorized)
	AuthRefreshTokenMismatch      = NewErrorCode(authRefreshTokenMismatch, "refresh token does not match stored token", http.StatusUnauthorized)
	AuthInternalServiceError      = NewErrorCode(authInternalServiceError, "internal service error", http.StatusInternalServerError)
	AuthOtpSendFailure            = NewErrorCode(authOtpSendFailure, "failed to send OTP", http.StatusInternalServerError)
	AuthOtpVerificationFailure    = NewErrorCode(authOtpVerificationFailure, "failed to verify OTP", http.StatusBadRequest)
	AuthPasswordOtpNotVerified    = NewErrorCode(authPasswordOtpNotVerified, "password OTP not verified", http.StatusBadRequest)
	AuthSignupFailed              = NewErrorCode(authSignupFailed, "signup failed", http.StatusBadRequest)
	AuthSigninFailed              = NewErrorCode(authSigninFailed, "signin failed", http.StatusInternalServerError)
	AuthUserNotVerified           = NewErrorCode(authUserNotVerified, "user not verified", http.StatusUnauthorized)
	AuthTokenVerificationFailed   = NewErrorCode(authTokenVerificationFailed, "token verification failed", http.StatusUnauthorized)
	AuthInvalidTokenSigningMethod = NewErrorCode(authInvalidTokenSigningMethod, "invalid token signing method", http.StatusUnauthorized)

	EmailRequired = NewErrorCode(emailRequired, "email is required", http.StatusBadRequest)
	EmailInvalid  = NewErrorCode(emailInvalid, "invalid email format", http.StatusBadRequest)

	PasswordRequired           = NewErrorCode(passwordRequired, "password is required", http.StatusBadRequest)
	PasswordTooShort           = NewErrorCode(passwordTooShort, "password must be at least 8 characters long", http.StatusBadRequest)
	PasswordTooLong            = NewErrorCode(passwordTooLong, "password must be at most 32 characters long", http.StatusBadRequest)
	PasswordMissingUppercase   = NewErrorCode(passwordMissingUppercase, "password must contain at least one uppercase letter", http.StatusBadRequest)
	PasswordMissingLowercase   = NewErrorCode(passwordMissingLowercase, "password must contain at least one lowercase letter", http.StatusBadRequest)
	PasswordMissingDigit       = NewErrorCode(passwordMissingDigit, "password must contain at least one digit", http.StatusBadRequest)
	PasswordMissingSpecialChar = NewErrorCode(passwordMissingSpecialChar, "password must contain at least one special character", http.StatusBadRequest)
	PasswordContainsWhitespace = NewErrorCode(passwordContainsWhitespace, "password cannot contain whitespace", http.StatusBadRequest)

	DBConnectionFailed   = NewErrorCode(dbConnectionFailed, "failed to connect to database", http.StatusInternalServerError)
	DBQueryFailed        = NewErrorCode(dbQueryFailed, "database query failed", http.StatusInternalServerError)
	DBInsertFailed       = NewErrorCode(dbInsertFailed, "database insert failed", http.StatusInternalServerError)
	DBUpdateFailed       = NewErrorCode(dbUpdateFailed, "database update failed", http.StatusInternalServerError)
	DBUserCreationFailed = NewErrorCode(dbUserCreationFailed, "failed to create user", http.StatusInternalServerError)
	DBUserQueryFailed    = NewErrorCode(dbUserQueryFailed, "failed to query user", http.StatusInternalServerError)
	DBEmailQueryFailed   = NewErrorCode(dbEmailQueryFailed, "failed to query user email", http.StatusInternalServerError)

	OBNameTooLong          = NewErrorCode(obNameTooLong, "name is too long", http.StatusBadRequest)
	OBNameTooShort         = NewErrorCode(obNameTooShort, "name is too short", http.StatusBadRequest)
	OBInvalidAge           = NewErrorCode(obInvalidAge, "age too short or big", http.StatusBadRequest)
	OBInvalidGender        = NewErrorCode(obInvalidGender, "invalid gender", http.StatusBadRequest)
	OBUserAlreadyOnboarded = NewErrorCode(obUserAlreadyOnboarded, "user already onboarded", http.StatusConflict)

	RedisConnectionFailed             = NewErrorCode(redisConnectionFailed, "failed to connect to Redis", http.StatusInternalServerError)
	RedisSetRefreshTokenFailed        = NewErrorCode(redisSetRefreshTokenFailed, "failed to set refresh token", http.StatusInternalServerError)
	RedisGetRefreshTokenFailed        = NewErrorCode(redisGetRefreshTokenFailed, "failed to get refresh token", http.StatusInternalServerError)
	RedisDeleteRefreshTokenFailed     = NewErrorCode(redisDeleteRefreshTokenFailed, "failed to delete refresh token", http.StatusInternalServerError)
	RedisGetOtpFailed                 = NewErrorCode(redisGetOtpFailed, "failed to get OTP", http.StatusInternalServerError)
	RedisSetOtpFailed                 = NewErrorCode(redisSetOtpFailed, "failed to set OTP", http.StatusInternalServerError)
	RedisSetPasswordResetKeyFailed    = NewErrorCode(redisSetPasswordResetKeyFailed, "failed to set password reset key", http.StatusInternalServerError)
	RedisDeletePasswordResetKeyFailed = NewErrorCode(redisDeletePasswordResetKeyFailed, "failed to delete password reset key", http.StatusInternalServerError)
	RedisDeleteOTPFailed              = NewErrorCode(redisDeleteOTPFailed, "failed to delete OTP", http.StatusInternalServerError)

	OtpInvalidRequest    = NewErrorCode(otpInvalidRequest, "invalid OTP request", http.StatusBadRequest)
	OtpEmptyEmailForUser = NewErrorCode(otpEmptyEmailForUser, "email empty for user", http.StatusBadRequest)
	OtpExpiredOrNotFound = NewErrorCode(otpExpiredOrNotFound, "OTP expired or not found", http.StatusGone)
	OtpInvalid           = NewErrorCode(otpInvalid, "invalid OTP", http.StatusBadRequest)
	OtpInvalidPurpose    = NewErrorCode(otpInvalidPurpose, "invalid OTP purpose", http.StatusBadRequest)
	OtpCodeMissing       = NewErrorCode(otpCodeMissing, "OTP code is required", http.StatusBadRequest)

	PhoenixEmailDeliveryFailed = NewErrorCode(phoenixEmailDeliveryFailed, "failed to deliver email", http.StatusInternalServerError)

	ServerMissingEnvVars         = NewErrorCode(serverMissingEnvVars, "no .env file found. Server cannot start", http.StatusInternalServerError)
	ServerStartupFailed          = NewErrorCode(serverStartupFailed, "server startup failed", http.StatusInternalServerError)
	ServerShutdownFailed         = NewErrorCode(serverShutdownFailed, "server shutdown error", http.StatusInternalServerError)
	ServerInternalError          = NewErrorCode(serverInternalError, "internal server error", http.StatusInternalServerError)
	ServerInvalidBody            = NewErrorCode(serverInvalidBody, "invalid request body", http.StatusBadRequest)
	ServerTooManyRequests        = NewErrorCode(serverTooManyRequests, "too many requests", http.StatusTooManyRequests)
	ServerHTTPServerError        = NewErrorCode(serverHTTPServerError, "HTTP server error", http.StatusInternalServerError)
	ServerBadRequest             = NewErrorCode(serverBadRequest, "bad request", http.StatusBadRequest)
	ServerUnauthorized           = NewErrorCode(serverUnauthorized, "unauthorized access", http.StatusUnauthorized)
	ServerJSONMarshalError       = NewErrorCode(serverJSONMarshalError, "error marshalling JSON", http.StatusInternalServerError)
	ServerJSONUnmarshalError     = NewErrorCode(serverJSONUnmarshalError, "error unmarshalling JSON", http.StatusBadRequest)
	ServerRequestCreationFailure = NewErrorCode(serverRequestCreationFailure, "failed to create request", http.StatusInternalServerError)
	ServerRequestDeliveryFailure = NewErrorCode(serverRequestDeliveryFailure, "failed to send Brevo request", http.StatusInternalServerError)
	ServerNon200ResponseError    = NewErrorCode(serverNon200ResponseError, "received non-200 response from API", http.StatusBadGateway)
)

// GetErrorByCode maps string codes to ErrorCode objects
func GetErrorByCode(code string) (*Code, bool) {
	errorMap := map[string]*Code{
		// Authentication
		authEmailDoesntExist:       AuthEmailDoesntExist,
		authEmailExists:            AuthEmailExists,
		authIncorrectPassword:      AuthIncorrectPassword,
		authInvalidBody:            AuthInvalidBody,
		authUserIDGenerationFailed: AuthUserIDGenerationFailed,
		authPasswordHashingFailed:  AuthPasswordHashingFailed,
		authTokenGenerationFailed:  AuthTokenGenerationFailed,
		authTokenInvalid:           AuthTokenInvalid,
		authUnauthorized:           AuthUnauthorized,
		authUserNotFound:           AuthUserNotFound,
		authInvalidRefreshToken:    AuthInvalidRefreshToken,
		authRefreshTokenMismatch:   AuthRefreshTokenMismatch,
		authInternalServiceError:   AuthInternalServiceError,
		authOtpSendFailure:         AuthOtpSendFailure,
		authOtpVerificationFailure: AuthOtpVerificationFailure,
		authPasswordOtpNotVerified: AuthPasswordOtpNotVerified,
		authUserNotVerified:        AuthUserNotVerified,

		// Email validation
		emailRequired: EmailRequired,
		emailInvalid:  EmailInvalid,

		// Password validation
		passwordRequired:           PasswordRequired,
		passwordTooShort:           PasswordTooShort,
		passwordTooLong:            PasswordTooLong,
		passwordMissingUppercase:   PasswordMissingUppercase,
		passwordMissingLowercase:   PasswordMissingLowercase,
		passwordMissingDigit:       PasswordMissingDigit,
		passwordMissingSpecialChar: PasswordMissingSpecialChar,
		passwordContainsWhitespace: PasswordContainsWhitespace,

		// Database
		dbConnectionFailed:   DBConnectionFailed,
		dbQueryFailed:        DBQueryFailed,
		dbInsertFailed:       DBInsertFailed,
		dbUpdateFailed:       DBUpdateFailed,
		dbUserCreationFailed: DBUserCreationFailed,
		dbUserQueryFailed:    DBUserQueryFailed,
		dbEmailQueryFailed:   DBEmailQueryFailed,

		// Onboarding
		obNameTooLong:          OBNameTooLong,
		obNameTooShort:         OBNameTooShort,
		obInvalidAge:           OBInvalidAge,
		obInvalidGender:        OBInvalidGender,
		obUserAlreadyOnboarded: OBUserAlreadyOnboarded,

		// Redis
		redisConnectionFailed:             RedisConnectionFailed,
		redisSetRefreshTokenFailed:        RedisSetRefreshTokenFailed,
		redisGetRefreshTokenFailed:        RedisGetRefreshTokenFailed,
		redisDeleteRefreshTokenFailed:     RedisDeleteRefreshTokenFailed,
		redisGetOtpFailed:                 RedisGetOtpFailed,
		redisSetPasswordResetKeyFailed:    RedisSetPasswordResetKeyFailed,
		redisDeletePasswordResetKeyFailed: RedisDeletePasswordResetKeyFailed,

		// OTP
		otpInvalidRequest:    OtpInvalidRequest,
		otpEmptyEmailForUser: OtpEmptyEmailForUser,
		otpExpiredOrNotFound: OtpExpiredOrNotFound,
		otpInvalid:           OtpInvalid,
		otpInvalidPurpose:    OtpInvalidPurpose,
		otpCodeMissing:       OtpCodeMissing,

		// Phoenix
		phoenixEmailDeliveryFailed: PhoenixEmailDeliveryFailed,

		// Server
		serverMissingEnvVars:         ServerMissingEnvVars,
		serverStartupFailed:          ServerStartupFailed,
		serverShutdownFailed:         ServerShutdownFailed,
		serverInternalError:          ServerInternalError,
		serverInvalidBody:            ServerInvalidBody,
		serverTooManyRequests:        ServerTooManyRequests,
		serverHTTPServerError:        ServerHTTPServerError,
		serverBadRequest:             ServerBadRequest,
		serverUnauthorized:           ServerUnauthorized,
		serverJSONMarshalError:       ServerJSONMarshalError,
		serverJSONUnmarshalError:     ServerJSONUnmarshalError,
		serverRequestCreationFailure: ServerRequestCreationFailure,
		serverRequestDeliveryFailure: ServerRequestDeliveryFailure,
		serverNon200ResponseError:    ServerNon200ResponseError,
	}

	err, exists := errorMap[code]
	return err, exists
}
