package mood

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	moodRepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/mood"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

type Service interface {
	LogMood(ctx context.Context, userId string, request mood.Request) (bool, *appError.Code)
}

type service struct {
	moodRepo moodRepo.Repository
}

func NewService(moodRepo moodRepo.Repository) Service {
	return &service{
		moodRepo: moodRepo,
	}
}
