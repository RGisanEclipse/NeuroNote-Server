package auth

import (
	"os"
	"time"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateJWT returns a signed JWT token with user ID and email
func GenerateToken(userId uint, email string) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", fmt.Errorf("JWT_SECRET environment variable is not set")
	}

	claims := jwt.MapClaims{
		"user_id": userId,
		"email":   email,
		"exp": time.Now().AddDate(1, 0, 0).Unix(), // Expires in 1 year
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}