package auth

type RefreshTokenServiceResponse struct {
	AccessToken  string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}