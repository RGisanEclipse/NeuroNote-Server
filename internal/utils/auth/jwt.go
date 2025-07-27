package auth

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
)
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func GenerateTokenPair(userId string, email string) (accessToken string, refreshToken string, err error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", "", errors.New(auth.JWTError.JWTSecretNotSet)
	}

	accessClaims := Claims{
		UserID: userId,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = at.SignedString([]byte(secret))
	if err != nil {
		return "", "", errors.New(auth.JWTError.TokenGenerationFailed)
	}

	refreshClaims := Claims{
		UserID: userId,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		},
	}

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = rt.SignedString([]byte(secret))
	return
}

func VerifyAccessToken(tokenString string) (*Claims, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New(auth.JWTError.JWTSecretNotSet)
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(auth.JWTError.InvalidTokenSigningMethod)
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New(auth.JWTError.TokenInvalid)
	}

	return claims, nil
}