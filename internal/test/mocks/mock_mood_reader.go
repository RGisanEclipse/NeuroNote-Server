package mocks

import (
	"context"

	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

// MockMoodReader is a simple reader backed by in-memory data.
type MockMoodReader struct {
	Entries []mood.Entry
	Err     error
}

func (m *MockMoodReader) GetMoodByDuration(ctx context.Context, userId string, from int64) ([]mood.Entry, error) {
	return m.Entries, m.Err
}
