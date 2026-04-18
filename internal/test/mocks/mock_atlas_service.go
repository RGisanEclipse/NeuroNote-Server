package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/atlas"
	syncModel "github.com/RGisanEclipse/AVYO-Server/internal/models/sync"
	"github.com/stretchr/testify/mock"
)

type MockAtlasService struct{ mock.Mock }

func (m *MockAtlasService) GetWeeklyMoodStripData(ctx context.Context, request atlas.MoodTrendRequest) (*atlas.MoodTrendResponse, *appError.Code) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		var err *appError.Code
		if args.Get(1) != nil {
			err = args.Get(1).(*appError.Code)
		}
		return nil, err
	}
	return args.Get(0).(*atlas.MoodTrendResponse), nil
}

func (m *MockAtlasService) GetMonthlyTopMoodsData(ctx context.Context, request atlas.MoodTrendRequest) (*atlas.MoodTop3Response, *appError.Code) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		var err *appError.Code
		if args.Get(1) != nil {
			err = args.Get(1).(*appError.Code)
		}
		return nil, err
	}
	return args.Get(0).(*atlas.MoodTop3Response), nil
}

func (m *MockAtlasService) GetDashboardData(ctx context.Context, request atlas.MoodTrendRequest) (*atlas.DashboardResponse, *appError.Code) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		var err *appError.Code
		if args.Get(1) != nil {
			err = args.Get(1).(*appError.Code)
		}
		return nil, err
	}
	return args.Get(0).(*atlas.DashboardResponse), nil
}

func (m *MockAtlasService) BulkSync(ctx context.Context, userID string, req syncModel.SyncRequest) *syncModel.SyncResponse {
	args := m.Called(ctx, userID, req)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*syncModel.SyncResponse)
}
