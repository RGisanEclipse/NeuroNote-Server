package nova

import (
	"context"
	"testing"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	activityModel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/activity"
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
				moodReader:     &mocks.MockMoodReader{Entries: tt.entries},
				activityReader: &mocks.MockActivityRepo{},
			}

			got, err := svc.GetMoodTrend(context.Background(), tt.request)

			if tt.wantErr != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.wantErr.Code, err.Code)
				assert.Nil(t, got)
				return
			}

			assert.Nil(t, err)
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
				moodReader:     &mocks.MockMoodReader{Entries: tt.entries},
				activityReader: &mocks.MockActivityRepo{},
			}

			got, err := svc.GetTopMoods(context.Background(), tt.request, tt.limit)

			if tt.wantErr != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.wantErr.Code, err.Code)
				assert.Nil(t, got)
				return
			}

			assert.Nil(t, err)
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

func TestService_GetStreakData(t *testing.T) {
	userID := "user123"

	tests := []struct {
		name         string
		streak       *activityModel.Streak
		getStreakErr error
		wantResp     *activityModel.StreakResponse
		wantErr      *appError.Code
	}{
		{
			name:     "no streak record returns empty response",
			streak:   nil,
			wantResp: &activityModel.StreakResponse{},
			wantErr:  nil,
		},
		{
			name: "existing streak is returned correctly",
			streak: &activityModel.Streak{
				UserID:         userID,
				CurrentStreak:  5,
				LongestStreak:  12,
				LastActiveDate: 1746057600,
			},
			wantResp: &activityModel.StreakResponse{
				CurrentStreak:  5,
				LongestStreak:  12,
				LastActiveDate: 1746057600,
			},
			wantErr: nil,
		},
		{
			name:         "DB error returns ServerInternalError",
			streak:       nil,
			getStreakErr: assert.AnError,
			wantResp:     nil,
			wantErr:      appError.ServerInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service{
				moodReader: &mocks.MockMoodReader{},
				activityReader: &mocks.MockActivityRepo{
					Streak:       tt.streak,
					GetStreakErr: tt.getStreakErr,
				},
			}

			got, err := svc.GetStreakData(context.Background(), userID)

			if tt.wantErr != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.wantErr.Code, err.Code)
				assert.Nil(t, got)
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.wantResp, got)
		})
	}
}

func TestService_GetActivityStats(t *testing.T) {
	userID := "user123"

	from := int64(1745452800) // some Monday midnight UTC
	to := int64(1745971200)   // 6 days later

	tests := []struct {
		name     string
		entries  []activityModel.DailyEntry
		rangeErr error
		wantResp *activityModel.StatsResponse
		wantErr  *appError.Code
	}{
		{
			name:     "no activity in range returns zeros",
			entries:  []activityModel.DailyEntry{},
			wantResp: &activityModel.StatsResponse{ActiveDays: 0, TotalVisits: 0},
			wantErr:  nil,
		},
		{
			name: "multiple days with varying visit counts",
			entries: []activityModel.DailyEntry{
				{UserID: userID, ActivityDate: from, VisitCount: 3},
				{UserID: userID, ActivityDate: from + 86400, VisitCount: 1},
				{UserID: userID, ActivityDate: from + 172800, VisitCount: 5},
			},
			wantResp: &activityModel.StatsResponse{ActiveDays: 3, TotalVisits: 9},
			wantErr:  nil,
		},
		{
			name:     "DB error returns ServerInternalError",
			rangeErr: assert.AnError,
			wantResp: nil,
			wantErr:  appError.ServerInternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &service{
				moodReader: &mocks.MockMoodReader{},
				activityReader: &mocks.MockActivityRepo{
					Entries:  tt.entries,
					RangeErr: tt.rangeErr,
				},
			}

			got, err := svc.GetActivityStats(context.Background(), userID, from, to)

			if tt.wantErr != nil {
				assert.NotNil(t, err)
				assert.Equal(t, tt.wantErr.Code, err.Code)
				assert.Nil(t, got)
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.wantResp, got)
		})
	}
}
