package onboarding

import (
	"context"

	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	"gorm.io/gorm"
)

type repo struct {
	db *gorm.DB
}

func NewOBDetailsRepository(db *gorm.DB) Repository {
	return &repo{db: db}
}

// SaveOnboardingDetails inserts the onboarding details for a user.
func (r *repo) SaveOnboardingDetails(ctx context.Context, data om.Model) error {
	return r.db.WithContext(ctx).Create(&data).Error
}

// IsOnboardedAlready checks whether onboarding details already exist for the given userID.
func (r *repo) IsOnboardedAlready(ctx context.Context, userID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&om.Model{}).
		Where("user_id = ?", userID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
