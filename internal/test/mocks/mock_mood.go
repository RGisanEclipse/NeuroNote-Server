package mocks

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"github.com/stretchr/testify/mock"
)

type MockMoodRepo struct{ mock.Mock }

func (m *MockMoodRepo) SaveMood(ctx context.Context, data mood.Entry) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockMoodRepo) GetMoodByDuration(ctx context.Context, userId string, from int64) ([]mood.Entry, error) {
	args := m.Called(ctx, userId, from)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]mood.Entry), args.Error(1)
}
