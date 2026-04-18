package nova

import (
	"context"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	activityModel "github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
	model "github.com/RGisanEclipse/AVYO-Server/internal/models/atlas"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/mood"
)

// MoodReader defines the dependency required to read mood entries.
type MoodReader interface {
	GetMoodByDuration(ctx context.Context, userId string, from int64) ([]mood.Entry, error)
}

// ActivityReader defines the dependency required to read activity and streak data.
type ActivityReader interface {
	GetStreak(ctx context.Context, userID string) (*activityModel.Streak, error)
	GetActivityByRange(ctx context.Context, userID string, from int64, to int64) ([]activityModel.DailyEntry, error)
}

// Service defines the interface for mood insights computations.
type Service interface {
	// GetMoodTrend computes the dominant mood per day within a given time range.
	GetMoodTrend(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code)

	// GetTopMoods computes the top N moods by frequency (with recency tie-breaker)
	// within a given time range.
	GetTopMoods(ctx context.Context, request model.MoodTrendRequest, limit int) (*model.MoodTop3Response, *appError.Code)

	// GetStreakData returns the current and longest streak for a user.
	GetStreakData(ctx context.Context, userID string) (*activityModel.StreakResponse, *appError.Code)

	// GetActivityStats returns the number of active days and total visits in a date range.
	// from and to are Unix epoch timestamps (start of day in UTC).
	GetActivityStats(ctx context.Context, userID string, from int64, to int64) (*activityModel.StatsResponse, *appError.Code)
}

type service struct {
	moodReader     MoodReader
	activityReader ActivityReader
}

// NewService constructs a nova insights service.
func NewService(moodReader MoodReader, activityReader ActivityReader) Service {
	return &service{
		moodReader:     moodReader,
		activityReader: activityReader,
	}
}
