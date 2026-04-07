package mocks

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"github.com/stretchr/testify/mock"
)

type MockMoodService struct{ mock.Mock }

func (m *MockMoodService) LogMood(ctx context.Context, userId string, request mood.Request) (bool, *appError.Code) {
	args := m.Called(ctx, userId, request)
	return args.Bool(0), args.Get(1).(*appError.Code)
}

func (m *MockMoodService) GetMood(ctx context.Context, userId string, days int) ([]mood.Entry, *appError.Code) {
	args := m.Called(ctx, userId, days)
	if args.Get(0) == nil {
		return nil, args.Get(1).(*appError.Code)
	}
	return args.Get(0).([]mood.Entry), args.Get(1).(*appError.Code)
}