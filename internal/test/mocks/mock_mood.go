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

