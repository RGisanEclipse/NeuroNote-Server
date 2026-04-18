package mocks

import (
	"context"

	activityModel "github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
)

// MockActivityRepo is an in-memory implementation of activity.Repository and nova.ActivityReader.
type MockActivityRepo struct {
	// UpsertDailyActivity
	UpsertErr   error
	UpsertCalls []int64

	// GetStreak
	Streak      *activityModel.Streak
	GetStreakErr error

	// SaveStreak
	SaveStreakErr error
	SavedStreak  *activityModel.Streak

	// GetActivityByRange
	Entries  []activityModel.DailyEntry
	RangeErr error
}

func (m *MockActivityRepo) UpsertDailyActivity(_ context.Context, _ string, date int64) error {
	m.UpsertCalls = append(m.UpsertCalls, date)
	return m.UpsertErr
}

func (m *MockActivityRepo) GetStreak(_ context.Context, _ string) (*activityModel.Streak, error) {
	return m.Streak, m.GetStreakErr
}

func (m *MockActivityRepo) SaveStreak(_ context.Context, streak activityModel.Streak) error {
	m.SavedStreak = &streak
	return m.SaveStreakErr
}

func (m *MockActivityRepo) GetActivityByRange(_ context.Context, _ string, _ int64, _ int64) ([]activityModel.DailyEntry, error) {
	return m.Entries, m.RangeErr
}
