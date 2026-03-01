package nova

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

// MoodReader defines the dependency required to read mood entries.
type MoodReader interface {
	GetMoodByDuration(ctx context.Context, userId string, from int64) ([]mood.Entry, error)
}

// Service defines the interface for mood insights computations.
type Service interface {
	// GetMoodTrend computes the dominant mood per day within a given time range.
	GetMoodTrend(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code)

	// GetTopMoods computes the top N moods by frequency (with recency tie-breaker)
	// within a given time range.
	GetTopMoods(ctx context.Context, request model.MoodTrendRequest, limit int) (*model.MoodTop3Response, *appError.Code)
}

type service struct {
	moodReader MoodReader
}

// NewService constructs a nova insights service.
func NewService(moodReader MoodReader) Service {
	return &service{
		moodReader: moodReader,
	}
}
