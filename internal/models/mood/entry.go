package mood

type Entry struct {
	ID        string      `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string      `gorm:"type:varchar(14);not null;index:idx_mood_user_created" json:"user_id"`
	Mood      Type        `gorm:"type:varchar(20);not null" json:"mood"`
	Reason    *ReasonType `gorm:"type:varchar(30)" json:"reason,omitempty"`
	CreatedAt int64       `gorm:"autoCreateTime;index:idx_mood_user_created" json:"created_at"`
	DeletedAt *int64      `gorm:"index" json:"deleted_at,omitempty"`
}

func (Entry) TableName() string {
	return "mood_entries"
}
