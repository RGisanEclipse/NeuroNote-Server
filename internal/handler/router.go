package handler

import (
	"github.com/gorilla/mux"

	authHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service"
)

// RegisterRoutes registers all routes for the application
func RegisterRoutes(router *mux.Router, services *service.Services) {
	authHandler.RegisterAuthRoutes(router, services.Auth)
}