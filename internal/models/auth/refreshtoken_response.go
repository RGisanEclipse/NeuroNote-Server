package auth

type RefreshTokenResponse struct {
	AccessToken  string `json:"token"`
}