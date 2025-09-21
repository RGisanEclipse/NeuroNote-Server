package auth

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	AccessToken string `json:"token"`
}

type RefreshTokenServiceResponse struct {
	AccessToken  string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}
