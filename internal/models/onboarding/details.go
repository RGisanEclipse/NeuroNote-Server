package onboarding

import "time"

type Model struct {
	UserID    string    `gorm:"primaryKey;size:14"`
	Name      string    `gorm:"size:255;not null"`
	Age       int       `gorm:"check:age >= 13 AND age <= 100"`
	Gender    int       `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (Model) TableName() string {
	return "onboarding_details"
}
