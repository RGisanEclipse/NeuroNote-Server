package mood

import (
	"context"

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
