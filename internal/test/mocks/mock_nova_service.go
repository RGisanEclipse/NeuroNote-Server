package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	activityModel "github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
	model "github.com/RGisanEclipse/AVYO-Server/internal/models/atlas"
)

// NovaTopCall captures a single call made to GetTopMoods.
type NovaTopCall struct {
	Req   model.MoodTrendRequest
	Limit int
}

// MockNovaService is a simple, stateful implementation of nova.Service used for tests.
type MockNovaService struct {
	TrendResponse *model.MoodTrendResponse
	TrendErr      *appError.Code

	TopResponse *model.MoodTop3Response
	TopErr      *appError.Code

	StreakResponse *activityModel.StreakResponse
	StreakErr      *appError.Code

	StatsResponse *activityModel.StatsResponse
	StatsErr      *appError.Code

	TrendCalls []model.MoodTrendRequest
	TopCalls   []NovaTopCall
}

func (m *MockNovaService) GetMoodTrend(ctx context.Context, req model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code) {
	m.TrendCalls = append(m.TrendCalls, req)
	if m.TrendErr != nil {
		return nil, m.TrendErr
	}
	return m.TrendResponse, nil
}

func (m *MockNovaService) GetTopMoods(ctx context.Context, req model.MoodTrendRequest, limit int) (*model.MoodTop3Response, *appError.Code) {
	m.TopCalls = append(m.TopCalls, NovaTopCall{
		Req:   req,
		Limit: limit,
	})
	if m.TopErr != nil {
		return nil, m.TopErr
	}
	return m.TopResponse, nil
}

func (m *MockNovaService) GetStreakData(ctx context.Context, userID string) (*activityModel.StreakResponse, *appError.Code) {
	if m.StreakErr != nil {
		return nil, m.StreakErr
	}
	return m.StreakResponse, nil
}

func (m *MockNovaService) GetActivityStats(ctx context.Context, userID string, from int64, to int64) (*activityModel.StatsResponse, *appError.Code) {
	if m.StatsErr != nil {
		return nil, m.StatsErr
	}
	return m.StatsResponse, nil
}
