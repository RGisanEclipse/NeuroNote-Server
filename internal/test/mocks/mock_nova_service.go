package mocks

import (
	"context"

	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
)

// NovaTopCall captures a single call made to GetTopMoods.
type NovaTopCall struct {
	Req   model.MoodTrendRequest
	Limit int
}

// MockNovaService is a simple, stateful implementation of nova.Service used for tests.
type MockNovaService struct {
	TrendResponse *model.MoodTrendResponse
	TrendErr      error

	TopResponse *model.MoodTop3Response
	TopErr      error

	TrendCalls []model.MoodTrendRequest
	TopCalls   []NovaTopCall
}

func (m *MockNovaService) GetMoodTrend(ctx context.Context, req model.MoodTrendRequest) (*model.MoodTrendResponse, error) {
	m.TrendCalls = append(m.TrendCalls, req)
	if m.TrendErr != nil {
		return nil, m.TrendErr
	}
	return m.TrendResponse, nil
}

func (m *MockNovaService) GetTopMoods(ctx context.Context, req model.MoodTrendRequest, limit int) (*model.MoodTop3Response, error) {
	m.TopCalls = append(m.TopCalls, NovaTopCall{
		Req:   req,
		Limit: limit,
	})
	if m.TopErr != nil {
		return nil, m.TopErr
	}
	return m.TopResponse, nil
}
