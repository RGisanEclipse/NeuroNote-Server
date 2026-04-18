package activity

import (
	"context"
	"errors"

	activityModel "github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Repository interface {
	UpsertDailyActivity(ctx context.Context, userID string, date int64) error
	GetStreak(ctx context.Context, userID string) (*activityModel.Streak, error)
	SaveStreak(ctx context.Context, streak activityModel.Streak) error
	GetActivityByRange(ctx context.Context, userID string, from int64, to int64) ([]activityModel.DailyEntry, error)
}

type repo struct {
	db *gorm.DB
}

func NewActivityRepository(db *gorm.DB) Repository {
	return &repo{db: db}
}

func (r *repo) UpsertDailyActivity(ctx context.Context, userID string, date int64) error {
	entry := activityModel.DailyEntry{
		UserID:       userID,
		ActivityDate: date,
		VisitCount:   1,
	}
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "user_id"}, {Name: "activity_date"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"visit_count": gorm.Expr("user_activity.visit_count + 1"),
			}),
		}).
		Create(&entry).Error
}

func (r *repo) GetStreak(ctx context.Context, userID string) (*activityModel.Streak, error) {
	var streak activityModel.Streak
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&streak).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &streak, err
}

func (r *repo) SaveStreak(ctx context.Context, streak activityModel.Streak) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"current_streak", "longest_streak", "last_active_date", "updated_at"}),
		}).
		Create(&streak).Error
}

func (r *repo) GetActivityByRange(ctx context.Context, userID string, from int64, to int64) ([]activityModel.DailyEntry, error) {
	var entries []activityModel.DailyEntry
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND activity_date >= ? AND activity_date <= ?", userID, from, to).
		Order("activity_date ASC").
		Find(&entries).Error
	return entries, err
}
