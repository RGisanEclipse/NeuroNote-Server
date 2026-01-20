package mocks

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/stretchr/testify/mock"
)

type MockAtlasService struct{ mock.Mock }

func (m *MockAtlasService) GetWeeklyMoodStripData(ctx context.Context, request atlas.MoodTrendRequest) (*atlas.MoodTrendResponse, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*atlas.MoodTrendResponse), args.Error(1)
}

func (m *MockAtlasService) GetMonthlyTopMoodsData(ctx context.Context, request atlas.MoodTrendRequest) (*atlas.MoodTop3Response, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*atlas.MoodTop3Response), args.Error(1)
}
