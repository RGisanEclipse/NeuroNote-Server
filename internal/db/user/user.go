package user

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/user"
	"gorm.io/gorm"
)

type repo struct{ db *gorm.DB }

func NewUserRepo(db *gorm.DB) Repository {
	return &repo{db}
}

func (r *repo) UserExists(ctx context.Context, email string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&user.Model{}).
		Where("email = ?", email).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *repo) UserExistsById(ctx context.Context, userId string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&user.Model{}).
		Where("user_id = ?", userId).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *repo) CreateUser(ctx context.Context, email, hash, userId string) (bool, error) {
	u := user.Model{UserID: userId, Email: email, PasswordHash: hash}
	if err := r.db.WithContext(ctx).Create(&u).Error; err != nil {
		return false, err
	}
	return true, nil
}

func (r *repo) GetUserCreds(ctx context.Context, email string) (*Creds, error) {
	var u user.Model
	err := r.db.WithContext(ctx).
		Select("user_id", "password_hash").
		Where("email = ?", email).
		First(&u).Error

	if err != nil {
		return nil, err
	}
	return &Creds{Id: u.UserID, PasswordHash: u.PasswordHash}, nil
}

func (r *repo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	var u user.Model
	err := r.db.WithContext(ctx).
		Select("is_verified").
		Where("user_id = ?", userId).
		First(&u).Error

	if err != nil {
		return false, err
	}
	return u.IsVerified, nil
}

func (r *repo) GetUserEmailById(ctx context.Context, userId string) (string, error) {
	var u user.Model
	err := r.db.WithContext(ctx).
		Select("email").
		Where("user_id = ?", userId).
		First(&u).Error

	if err != nil {
		return "", err
	}
	return u.Email, nil
}

func (r *repo) MarkUserVerified(ctx context.Context, userId string) error {
	return r.db.WithContext(ctx).
		Model(&user.Model{}).
		Where("user_id = ?", userId).
		Update("is_verified", true).Error
}

func (r *repo) ResetPassword(ctx context.Context, userId, password string) error {
	return r.db.WithContext(ctx).
		Model(&user.Model{}).
		Where("user_id = ?", userId).
		Update("password_hash", password).Error
}
