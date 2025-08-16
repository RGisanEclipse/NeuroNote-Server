package user

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/user"
	"gorm.io/gorm"
)

type gormRepo struct{ db *gorm.DB }

// NewGormRepo returns a concrete repo backed by Gorm/PostgreSQL.
func NewGormRepo(db *gorm.DB) Repository {
	return &gormRepo{db}
}

// ---------------------------
// interface methods
// ---------------------------

func (r *gormRepo) UserExists(ctx context.Context, email string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&user.UserModel{}).
		Where("email = ?", email).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *gormRepo) CreateUser(ctx context.Context, email, hash, userId string) (bool, error) {
	u := user.UserModel{UserID: userId, Email: email, PasswordHash: hash}
	if err := r.db.WithContext(ctx).Create(&u).Error; err != nil {
		return false, err
	}
	return true, nil
}

func (r *gormRepo) GetUserCreds(ctx context.Context, email string) (*Creds, error) {
	var u user.UserModel
	err := r.db.WithContext(ctx).
		Select("user_id", "password_hash").
		Where("email = ?", email).
		First(&u).Error

	if err != nil {
		return nil, err
	}
	return &Creds{Id: u.UserID, PasswordHash: u.PasswordHash}, nil
}

func (r *gormRepo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	var u user.UserModel
	err := r.db.WithContext(ctx).
		Select("is_verified").
		Where("user_id = ?", userId).
		First(&u).Error

	if err != nil {
		return false, err
	}
	return u.IsVerified, nil
}

func (r *gormRepo) GetUserEmailById(ctx context.Context, userId string) (string, error) {
	var u user.UserModel
	err := r.db.WithContext(ctx).
		Select("email").
		Where("user_id = ?", userId).
		First(&u).Error
		
	if err != nil {
		return "", err
	}
	return u.Email, nil
}