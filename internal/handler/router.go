package handler

import (
	"github.com/gorilla/mux"

	authHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/public"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private"
)

// RegisterPublicRoutes registers all public routes for the application
func RegisterPublicRoutes(router *mux.Router, services *public.PublicServices) {
	authHandler.RegisterAuthRoutes(router, services.Auth)
}
// RegisterPrivateRoutes registers all private routes for the application
func RegisterPrivateRoutes(router *mux.Router, services *private.PrivateServices) {
	// Currently there are no private routes to register, but all the private routes registrations will go here
}