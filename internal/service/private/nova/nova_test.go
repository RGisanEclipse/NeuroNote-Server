package nova

import (
	"context"
	"testing"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
)

func TestService_GetMoodTrend(t *testing.T) {
	tz := *time.UTC
	base := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	userID := "user123"

	happy := mood.Happy
	worried := mood.Worried

	tests := []struct {
		name     string
		request  model.MoodTrendRequest
		entries  []mood.Entry
		wantData map[string]*mood.Type
		wantErr  *appError.Code
	}{
		{
			name: "single day dominant by count",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base.Add(-time.Hour),
				EndTime:   base.Add(time.Hour),
			},
			entries: []mood.Entry{
				{UserID: userID, Mood: happy, CreatedAt: base.Add(-30 * time.Minute).Unix()},
				{UserID: userID, Mood: happy, CreatedAt: base.Unix()},
				{UserID: userID, Mood: worried, CreatedAt: base.Add(30 * time.Minute).Unix()},
			},
			wantData: map[string]*mood.Type{
				base.Format("2006-01-02"): &happy,
			},
			wantErr: nil,
		},
		{
			name: "dominant mood chosen by recency on tie",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base.Add(-time.Hour),
				EndTime:   base.Add(time.Hour),
			},
			entries: []mood.Entry{
				{UserID: userID, Mood: happy, CreatedAt: base.Add(-30 * time.Minute).Unix()},
				{UserID: userID, Mood: worried, CreatedAt: base.Add(-20 * time.Minute).Unix()},
				{UserID: userID, Mood: happy, CreatedAt: base.Add(-10 * time.Minute).Unix()},
				{UserID: userID, Mood: worried, CreatedAt: base.Add(5 * time.Minute).Unix()},
			},
			wantData: map[string]*mood.Type{
				base.Format("2006-01-02"): &worried,
			},
			wantErr: nil,
		},
		{
			name: "invalid range returns MDInvalidDaysRange",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base,
				EndTime:   base.Add(-time.Hour),
			},
			entries:  nil,
			wantData: nil,
			wantErr:  appError.MDInvalidDaysRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service{
				moodReader: &mocks.MockMoodReader{
					Entries: tt.entries,
					Err:     nil,
				},
			}

			got, err := svc.GetMoodTrend(context.Background(), tt.request)

			if tt.wantErr != nil {
				assert.Error(t, err)
				appErr, ok := err.(*appError.Code)
				if assert.True(t, ok, "error should be of type *appError.Code") {
					assert.Equal(t, tt.wantErr.Code, appErr.Code)
				}
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, len(tt.wantData), len(got.Data))
				for day, expectedMood := range tt.wantData {
					actual := got.Data[day]
					if expectedMood == nil {
						assert.Nil(t, actual)
					} else {
						if assert.NotNil(t, actual, "expected mood for day %s", day) {
							assert.Equal(t, *expectedMood, *actual)
						}
					}
				}
			}
		})
	}
}

func TestService_GetTopMoods(t *testing.T) {
	tz := *time.UTC
	base := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	userID := "user123"

	tests := []struct {
		name        string
		request     model.MoodTrendRequest
		entries     []mood.Entry
		limit       int
		wantOrder   []mood.Type
		wantErr     *appError.Code
		expectEmpty bool
	}{
		{
			name: "no entries returns empty slice",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base.Add(-24 * time.Hour),
				EndTime:   base,
			},
			entries:     []mood.Entry{},
			limit:       3,
			wantOrder:   nil,
			wantErr:     nil,
			expectEmpty: true,
		},
		{
			name: "top moods ordered by count and recency",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base.Add(-24 * time.Hour),
				EndTime:   base.Add(24 * time.Hour),
			},
			entries: []mood.Entry{
				// happy: 3 entries
				{UserID: userID, Mood: mood.Happy, CreatedAt: base.Add(-23 * time.Hour).Unix()},
				{UserID: userID, Mood: mood.Happy, CreatedAt: base.Add(-22 * time.Hour).Unix()},
				{UserID: userID, Mood: mood.Happy, CreatedAt: base.Add(-21 * time.Hour).Unix()},
				// worried: 2 entries, more recent than some happy
				{UserID: userID, Mood: mood.Worried, CreatedAt: base.Add(-2 * time.Hour).Unix()},
				{UserID: userID, Mood: mood.Worried, CreatedAt: base.Add(-1 * time.Hour).Unix()},
				// down: 2 entries, but older than worried
				{UserID: userID, Mood: mood.Down, CreatedAt: base.Add(-10 * time.Hour).Unix()},
				{UserID: userID, Mood: mood.Down, CreatedAt: base.Add(-9 * time.Hour).Unix()},
			},
			limit:       3,
			wantOrder:   []mood.Type{mood.Happy, mood.Worried, mood.Down},
			wantErr:     nil,
			expectEmpty: false,
		},
		{
			name: "limit smaller than distinct moods",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base.Add(-24 * time.Hour),
				EndTime:   base.Add(24 * time.Hour),
			},
			entries: []mood.Entry{
				{UserID: userID, Mood: mood.Happy, CreatedAt: base.Unix()},
				{UserID: userID, Mood: mood.Happy, CreatedAt: base.Add(1 * time.Hour).Unix()},
				{UserID: userID, Mood: mood.Worried, CreatedAt: base.Add(2 * time.Hour).Unix()},
			},
			limit:       1,
			wantOrder:   []mood.Type{mood.Happy},
			wantErr:     nil,
			expectEmpty: false,
		},
		{
			name: "invalid range returns MDInvalidDaysRange",
			request: model.MoodTrendRequest{
				UserId:    userID,
				TimeZone:  tz,
				StartTime: base,
				EndTime:   base.Add(-time.Hour),
			},
			entries:     nil,
			limit:       3,
			wantOrder:   nil,
			wantErr:     appError.MDInvalidDaysRange,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service{
				moodReader: &mocks.MockMoodReader{
					Entries: tt.entries,
					Err:     nil,
				},
			}

			got, err := svc.GetTopMoods(context.Background(), tt.request, tt.limit)

			if tt.wantErr != nil {
				assert.Error(t, err)
				appErr, ok := err.(*appError.Code)
				if assert.True(t, ok, "error should be of type *appError.Code") {
					assert.Equal(t, tt.wantErr.Code, appErr.Code)
				}
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			if tt.expectEmpty {
				assert.NotNil(t, got)
				assert.Len(t, got.Data, 0)
				return
			}

			if assert.NotNil(t, got) {
				if assert.GreaterOrEqual(t, len(got.Data), len(tt.wantOrder)) {
					for i, moodType := range tt.wantOrder {
						assert.Equal(t, moodType, got.Data[i].Mood)
					}
				}
			}
		})
	}
}
