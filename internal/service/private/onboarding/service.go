package onboarding

import (
	"context"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	onboardingRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/onboarding"
	userRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/user"
	om "github.com/RGisanEclipse/AVYO-Server/internal/models/onboarding"
)

type Service interface {
	OnboardUser(ctx context.Context, userId string, onboardingData om.Model) (bool, *appError.Code)
}

type service struct {
	userRepo       userRepo.Repository
	onboardingRepo onboardingRepo.Repository
}

func NewService(userRepo userRepo.Repository, onboardingRepo onboardingRepo.Repository) Service {
	return &service{
		userRepo:       userRepo,
		onboardingRepo: onboardingRepo,
	}
}
