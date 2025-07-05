package handler

import (
	auth "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	"github.com/gorilla/mux"
)

// RegisterRoutes registers all routes for the application
func RegisterRoutes(router *mux.Router) {
	auth.RegisterAuthRoutes(router)
}