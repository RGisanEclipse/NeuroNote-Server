package rate

var routeLimits = map[string]int{
	"/api/v1/auth/signup":                 5,
	"/api/v1/auth/signup/otp":             3,
	"/api/v1/auth/signup/otp/verify":      5,
	"/api/v1/auth/signin":                 10,
	"/api/v1/auth/token/refresh":          20,
	"/api/v1/auth/password/forgot":        3,
	"/api/v1/auth/password/forgot/verify": 5,
	"/api/v1/auth/password/reset":         3,
}
