package onboarding

import (
	"context"

	om "github.com/RGisanEclipse/AVYO-Server/internal/models/onboarding"
)

// Repository defines the onboarding data persistence layer.
type Repository interface {
	SaveOnboardingDetails(ctx context.Context, data om.Model) error
	IsOnboardedAlready(ctx context.Context, userID string) (bool, error)
}
