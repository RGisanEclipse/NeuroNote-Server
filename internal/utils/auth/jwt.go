package auth

import (
	"os"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func GenerateTokenPair(userId string, email string) (accessToken string, refreshToken string, err error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		logger.Error(appError.ServerMissingEnvVars.Message, nil, appError.ServerMissingEnvVars, logrus.Fields{
			"message": "JWT Secret is not set in the environment",
		})
		return "", "", appError.ServerMissingEnvVars
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
		return "", "", appError.AuthTokenGenerationFailed
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

func VerifyAuthToken(tokenString string) (*Claims, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		logger.Error(appError.ServerMissingEnvVars.Message, nil, appError.ServerMissingEnvVars, logrus.Fields{
			"message": "JWT Secret is not set in the environment",
		})
		return nil, appError.ServerMissingEnvVars
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, appError.AuthInvalidTokenSigningMethod
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, appError.AuthTokenInvalid
	}

	return claims, nil
}
