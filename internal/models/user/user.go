package user

type UserModel struct {
	UserID       string `gorm:"primaryKey;size:14"`
	Email        string    `gorm:"uniqueIndex;size:255;not null"`
	PasswordHash string    `gorm:"size:255;not null"`
	IsVerified   bool      `gorm:"not null;default:false"`
	CreatedAt    int64  `gorm:"autoCreateTime"`
}

func (UserModel) TableName() string {
	return "users"
}