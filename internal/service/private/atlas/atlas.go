package atlas

import (
	"context"
	"time"

	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
)

func (s *service) GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, error) {
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

func (s *service) GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, error) {
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

func (s *service) GetDashboardData(ctx context.Context, request model.MoodTrendRequest) (*model.DashboardResponse, error) {
	weekly, weeklyErr := s.GetWeeklyMoodStripData(ctx, request)
	monthly, monthlyErr := s.GetMonthlyTopMoodsData(ctx, request)

	resp := &model.DashboardResponse{}
	if weeklyErr == nil && weekly != nil {
		resp.WeeklyMoodStrip = weekly.Data
	}
	if monthlyErr == nil && monthly != nil {
		resp.MonthlyTopMoods = monthly.Data
	}

	return resp, nil
}
