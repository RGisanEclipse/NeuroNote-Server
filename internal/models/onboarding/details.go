package onboarding

type Model struct {
	UserID    string `gorm:"primaryKey;size:14"`
	Name      string `gorm:"size:255;not null"`
	Age       int    `gorm:"check:age >= 13 AND age <= 100"`
	Gender    int    `gorm:"not null"`
	CreatedAt int64  `gorm:"autoCreateTime"`
	DeletedAt *int64 `gorm:"index"`
}

func (Model) TableName() string {
	return "onboarding_details"
}
