package auth

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	DeviceId     string `json:"deviceId"`
}

type RefreshTokenResponse struct {
	AccessToken string `json:"token"`
}

type RefreshTokenServiceResponse struct {
	AccessToken  string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}
