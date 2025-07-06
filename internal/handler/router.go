package handler

import (
	"github.com/gorilla/mux"

	authHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	authService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/auth"
)

// RegisterRoutes registers all routes for the application
func RegisterRoutes(router *mux.Router, authService *authService.Service) {
	authHandler.RegisterAuthRoutes(router, authService)
}