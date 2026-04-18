package mood

import (
	"context"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	moodRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/mood"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/mood"
)

type Service interface {
	LogMood(ctx context.Context, userId string, request mood.Request) (bool, *appError.Code)
	GetMood(ctx context.Context, userId string, days int) ([]mood.Entry, *appError.Code)
}

type service struct {
	moodRepo moodRepo.Repository
}

func NewService(moodRepo moodRepo.Repository) Service {
	return &service{
		moodRepo: moodRepo,
	}
}
