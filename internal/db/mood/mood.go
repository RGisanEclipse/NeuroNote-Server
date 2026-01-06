package mood

import (
	"context"
	"time"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"gorm.io/gorm"
)

type repo struct {
	db *gorm.DB
}

func NewMoodRepository(db *gorm.DB) Repository {
	return &repo{db: db}
}

func (r *repo) SaveMood(ctx context.Context, data mood.Entry) error {
	return r.db.WithContext(ctx).Create(&data).Error
}

func (r *repo) GetMoodByDuration(ctx context.Context, userId string, from time.Time) ([]mood.Entry, error) {

	var entries []mood.Entry

	err := r.db.WithContext(ctx).
		Where("user_id = ? AND created_at >= ?", userId, from).
		Order("created_at DESC").
		Find(&entries).Error

	return entries, err
}
