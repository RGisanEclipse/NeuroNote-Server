package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/auth"
)

// RegisterAuthRoutes wires up /signup and /signin endpoints
func RegisterAuthRoutes(router *mux.Router) {
	router.HandleFunc("/signup", signupHandler).Methods("POST")
	router.HandleFunc("/signin", signinHandler).Methods("POST")
}

// signupHandler handles user registration
func signupHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req authmodel.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn("Invalid signup request body", err)
		response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
			Success: false,
			Message: server.ServerError.InvalidBody,
		})
		return
	}

	token, err := authservice.Signup(ctx, req.Email, req.Password)
	if err != nil {
		logger.Warn("Signup failed", err, logrus.Fields{
			"email": req.Email,
		})
		response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	response.WriteJSON(w, http.StatusOK, authmodel.AuthResponse{
		Success: true,
		Message: "Account created successfully",
		Token:   token,
	})
}

// signinHandler handles user login
func signinHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req authmodel.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn("Invalid signin request body", err)
		response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
			Success: false,
			Message: server.ServerError.InvalidBody,
		})
		return
	}

	token, err := authservice.Signin(ctx, req.Email, req.Password)
	if err != nil {
		logger.Warn("Signin failed", err, logrus.Fields{
			"email": req.Email,
		})
		response.WriteJSON(w, http.StatusUnauthorized, authmodel.AuthResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	response.WriteJSON(w, http.StatusOK, authmodel.AuthResponse{
		Success: true,
		Message: "Logged in successfully",
		Token:   token,
	})
}