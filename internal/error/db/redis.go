package db

type RedisErrorMessages struct {
	ConnectionFailed             string
	SetRefreshTokenFailed        string
	GetRefreshTokenFailed        string
	DeleteRefreshTokenFailed     string
	GetOTPFailed                 string
	SetPasswordResetKeyFailed    string
	DeletePasswordResetKeyFailed string
}

var Redis = RedisErrorMessages{
	ConnectionFailed:             "failed to connect to database",
	SetRefreshTokenFailed:        "failed to set refresh token",
	GetRefreshTokenFailed:        "failed to get refresh token",
	DeleteRefreshTokenFailed:     "failed to delete refresh token",
	GetOTPFailed:                 "failed to get OTP",
	SetPasswordResetKeyFailed:    "Set password reset key failed",
	DeletePasswordResetKeyFailed: "Delete password reset key failed",
}
