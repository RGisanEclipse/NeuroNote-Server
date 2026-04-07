package handler

import (
	"github.com/gorilla/mux"

	atlasHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/atlas"
	authHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/auth"
	moodHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/mood"
	onboardingHandler "github.com/RGisanEclipse/NeuroNote-Server/internal/handler/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/public"
)

// RegisterPublicRoutes registers all public routes for the application
func RegisterPublicRoutes(router *mux.Router, services *public.Services) {
	authHandler.RegisterAuthRoutes(router, services.Auth)
}

// RegisterPrivateRoutes registers all private routes for the application
func RegisterPrivateRoutes(router *mux.Router, services *private.Services) {
	// Currently there are no private routes to register, but all the private routes registrations will go here
	onboardingHandler.RegisterOnboardingRoutes(router, services.Onboarding)
	moodHandler.RegisterMoodRoutes(router, services.Mood)
	atlasHandler.RegisterDashboardRoutes(router, services.Atlas)
}
