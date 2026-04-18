package atlas

import (
	"time"

	activityModel "github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/mood"
)

type MoodAggregate struct {
	DayCounts map[string]map[mood.Type]int
	DayLatest map[string]map[mood.Type]int64
	Totals    map[mood.Type]int
	Latest    map[mood.Type]int64
	Total     int
	Days      int
	StartDay  time.Time
}

type MoodTrendRequest struct {
	UserId    string
	TimeZone  time.Location
	StartTime time.Time
	EndTime   time.Time
}

type MoodTrendResponse struct {
	Data map[string]*mood.Type
}

type MoodPercentage struct {
	Mood       mood.Type `json:"mood"`
	Percentage float64   `json:"percentage"`
}

type MoodTop3Response struct {
	Data []MoodPercentage `json:"data"`
}

type DashboardResponse struct {
	WeeklyMoodStrip map[string]*mood.Type         `json:"weeklyMoodStrip"`
	MonthlyTopMoods []MoodPercentage              `json:"monthlyTopMoods"`
	Streak          *activityModel.StreakResponse `json:"streak"`
}
