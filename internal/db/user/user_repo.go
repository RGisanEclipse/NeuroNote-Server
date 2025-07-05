package user

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/common"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/user"
	"gorm.io/gorm"
)

// UserExists checks if a user with the email exists
func UserExists(ctx context.Context, email string) (bool, error) {
	var count int64
	if err := common.DB.WithContext(ctx).
		Model(&user.UserModel{}).
		Where("email = ?", email).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateUser inserts a new user record
func CreateUser(ctx context.Context, email, hash string) (uint, error) {
    user := user.UserModel{Email: email, PasswordHash: hash}
    if err := common.DB.WithContext(ctx).Create(&user).Error; err != nil {
        return 0, err
    }
    return user.ID, nil
}


func GetUserCreds(ctx context.Context, email string) (uint, string, error) {
	var u user.UserModel
	err := common.DB.WithContext(ctx).
		Select("id", "password_hash").
		Where("email = ?", email).
		First(&u).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return 0, "", err 
		}
		return 0, "", err
	}
	return u.ID, u.PasswordHash, nil
}