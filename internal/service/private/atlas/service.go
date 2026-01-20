package atlas

import (
	"context"

	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

type MoodReader interface {
	GetMoodByDuration(ctx context.Context, userId string, from int64) ([]mood.Entry, error)
}

type service struct {
	moodReader MoodReader
}

func NewService(moodReader MoodReader) Service {
	return &service{
		moodReader: moodReader,
	}
}

type Service interface {
	GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, error)
	GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, error)
}
