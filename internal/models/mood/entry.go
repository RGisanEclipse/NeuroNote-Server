package mood

import "time"

type Entry struct {
	ID        string      `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string      `gorm:"type:uuid;not null;index:idx_mood_user_created" json:"user_id"`
	Mood      Type        `gorm:"type:varchar(20);not null" json:"mood"`
	Reason    *ReasonType `gorm:"type:varchar(30)" json:"reason,omitempty"`
	CreatedAt time.Time   `gorm:"not null;index:idx_mood_user_created" json:"created_at"`
}

func (Entry) TableName() string {
	return "mood_entries"
}
