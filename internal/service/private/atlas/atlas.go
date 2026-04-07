package atlas

import (
	"context"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	activityModel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/activity"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
)

func (s *service) GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code) {
	tz := &request.TimeZone
	if request.TimeZone.String() == "" {
		tz = time.UTC
	}

	now := time.Now().In(tz)
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, tz)
	startOfWeek := startOfToday.AddDate(0, 0, -int(startOfToday.Weekday()))
	endOfWeek := startOfWeek.AddDate(0, 0, 7).Add(-time.Nanosecond)
	request.StartTime = startOfWeek
	request.EndTime = endOfWeek
	return s.nova.GetMoodTrend(ctx, request)
}

func (s *service) GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, *appError.Code) {
	tz := &request.TimeZone
	if request.TimeZone.String() == "" {
		tz = time.UTC
	}

	now := time.Now().In(tz)
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, tz)
	request.StartTime = startOfToday.AddDate(0, 0, -29)
	request.EndTime = now

	return s.nova.GetTopMoods(ctx, request, 3)
}

func (s *service) GetDashboardData(ctx context.Context, request model.MoodTrendRequest) (*model.DashboardResponse, *appError.Code) {
	s.recordActivity(ctx, request.UserId)

	weekly, weeklyErr := s.GetWeeklyMoodStripData(ctx, request)
	monthly, monthlyErr := s.GetMonthlyTopMoodsData(ctx, request)
	streak, _ := s.nova.GetStreakData(ctx, request.UserId)

	resp := &model.DashboardResponse{}
	if weeklyErr == nil && weekly != nil {
		resp.WeeklyMoodStrip = weekly.Data
	}
	if monthlyErr == nil && monthly != nil {
		resp.MonthlyTopMoods = monthly.Data
	}
	resp.Streak = streak

	return resp, nil
}

func (s *service) recordActivity(ctx context.Context, userID string) {
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Unix()
	yesterday := time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, time.UTC).Unix()

	if err := s.activityRepo.UpsertDailyActivity(ctx, userID, today); err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logger.Fields{"userId": userID})
		return
	}

	streak, err := s.activityRepo.GetStreak(ctx, userID)
	if err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logger.Fields{"userId": userID})
		return
	}

	if streak != nil && streak.LastActiveDate == today {
		return
	}

	newCurrent := 1
	newLongest := 1
	if streak != nil {
		newLongest = streak.LongestStreak
		if streak.LastActiveDate == yesterday {
			newCurrent = streak.CurrentStreak + 1
		}
		if newCurrent > newLongest {
			newLongest = newCurrent
		}
	}

	if err := s.activityRepo.SaveStreak(ctx, activityModel.Streak{
		UserID:         userID,
		CurrentStreak:  newCurrent,
		LongestStreak:  newLongest,
		LastActiveDate: today,
	}); err != nil {
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logger.Fields{"userId": userID})
	}
}
