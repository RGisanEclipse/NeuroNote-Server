package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
)

func RegisterAuthRoutes(router *mux.Router, svc authservice.AuthService) {
	router.HandleFunc("/api/v1/auth/signup", signupHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signin", signinHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/token/refresh", refreshTokenHandler(svc)).Methods("POST")
}


func signupHandler(svc authservice.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err)
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: server.ServerError.BadRequest,
			})
			return
		}
		if err := req.Validate(); err != nil {
			logger.Warn(server.ServerError.BadRequest, err, logrus.Fields{
				"email": req.Email,
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}
		
		res, err := svc.Signup(ctx, req.Email, req.Password)
		if err != nil {
			logger.Warn("Signup failed", err, logrus.Fields{
				"email": req.Email,
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}
		logger.Info("Response from signup handler", logrus.Fields{
			"email": req.Email,
			"requestId": reqID,
			"success": res.Success,
			"message": res.Message, 
			"isVerified": res.IsVerified,
		})

		http.SetCookie(w, &http.Cookie{
            Name:     "refreshToken",
            Value:    res.RefreshToken,
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
            Path:     "/",
            MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
        })

		response.WriteJSON(w, http.StatusOK, authmodel.AuthResponse{
			Success: res.Success,
			Message: res.Message,
			AccessToken:   res.AccessToken,
			IsVerified: res.IsVerified,
		})
	}
}

func signinHandler(svc authservice.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err)
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: server.ServerError.BadRequest,
			})
			return
		}

		res, err := svc.Signin(ctx, req.Email, req.Password)
		if err != nil {
			logger.Warn("Signin failed", err, logrus.Fields{
				"email": req.Email,
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusUnauthorized, authmodel.AuthResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
            Name:     "refreshToken",
            Value:    res.RefreshToken,
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
            Path:     "/",
            MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
        })

		response.WriteJSON(w, http.StatusOK, authmodel.AuthResponse{
			Success: res.Success,
			Message: res.Message,
			AccessToken:  res.AccessToken,
			IsVerified: res.IsVerified,
		})
	}
}

func refreshTokenHandler(svc authservice.AuthService) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusBadRequest, authmodel.RefreshTokenResponse{
				AccessToken:  "",
			})
			return
		}

		res, err := svc.RefreshToken(ctx, req.RefreshToken)
		if err != nil{
			logger.Warn("Refresh token failed", err, logrus.Fields{
				"refreshToken": req.RefreshToken,
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusUnauthorized, authmodel.RefreshTokenResponse{
				AccessToken:  "",
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
            Name:     "refreshToken",
            Value:    res.RefreshToken,
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
            Path:     "/",
            MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
        })

		response.WriteJSON(w, http.StatusOK, authmodel.RefreshTokenResponse{
			AccessToken:  res.AccessToken,
		})
	}
}