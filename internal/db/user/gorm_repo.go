package user

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/utils/types"
	typeErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/types"
	"gorm.io/gorm"
)

type gormRepo struct{ db *gorm.DB }

// NewGormRepo returns a concrete repo backed by Gorm/PostgreSQL.
func NewGormRepo(db *gorm.DB) Repository {
	return &gormRepo{db}
}

// interface methods 

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

func (r *gormRepo) CreateUser(ctx context.Context, email, hash string) (string, error) {
	u := user.UserModel{Email: email, PasswordHash: hash}
	if err := r.db.WithContext(ctx).Create(&u).Error; err != nil {
		return "0", err
	}
	userId := types.ConvertUintToString(u.ID)
	return userId, nil
}

func (r *gormRepo) GetUserCreds(ctx context.Context, email string) (*Creds, error) {
	var u user.UserModel
	err := r.db.WithContext(ctx).
		Select("id", "password_hash").
		Where("email = ?", email).
		First(&u).Error

	if err != nil {
		return nil, err 
	}
	userId := types.ConvertUintToString(u.ID)
	return &Creds{Id: userId, PasswordHash: u.PasswordHash}, nil
}

func (r *gormRepo) IsUserVerified(ctx context.Context, userId string) (bool, error) {
	var u user.UserModel
	userID, err := types.ConvertStringToUint(userId)
	if err != nil {
		logger.Error(typeErr.TypeError.TypeCastingError, err, logger.Fields{"userID": userId})
		return false, err
	}
	dberror := r.db.WithContext(ctx).
		Select("is_verified").
		First(&u, userID).Error
	if dberror!= nil {
		return false, dberror
	}
	return u.IsVerified, nil
}