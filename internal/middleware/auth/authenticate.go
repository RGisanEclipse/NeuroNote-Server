package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/utils/auth"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, error.AuthUnauthorized.Message, http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, error.AuthUnauthorized.Message, http.StatusUnauthorized)
			return
		}

		token := parts[1]
		claims, err := auth.VerifyAuthToken(token)
		if err != nil {
			logger.Warn(error.AuthTokenVerificationFailed.Message, err, error.AuthTokenVerificationFailed)
			http.Error(w, error.AuthUnauthorized.Message, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), user.UserIdKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
