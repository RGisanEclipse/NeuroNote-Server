package activity

type DailyEntry struct {
	UserID       string `gorm:"type:varchar(14);not null;primaryKey"`
	ActivityDate int64  `gorm:"not null;primaryKey"`
	VisitCount   int    `gorm:"not null;default:1"`
}

func (DailyEntry) TableName() string { return "user_activity" }

type Streak struct {
	UserID         string `gorm:"type:varchar(14);primaryKey"`
	CurrentStreak  int    `gorm:"not null;default:0"`
	LongestStreak  int    `gorm:"not null;default:0"`
	LastActiveDate int64  `gorm:"not null;default:0"`
	UpdatedAt      int64  `gorm:"autoUpdateTime"`
}

func (Streak) TableName() string { return "user_streaks" }

type StreakResponse struct {
	CurrentStreak  int   `json:"currentStreak"`
	LongestStreak  int   `json:"longestStreak"`
	LastActiveDate int64 `json:"lastActiveDate,omitempty"`
}

type StatsResponse struct {
	ActiveDays  int `json:"activeDays"`
	TotalVisits int `json:"totalVisits"`
}
