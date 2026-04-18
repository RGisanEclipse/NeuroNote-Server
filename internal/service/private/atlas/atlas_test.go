package atlas

import (
	"context"
	"testing"
	"time"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	activityModel "github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
	model "github.com/RGisanEclipse/AVYO-Server/internal/models/atlas"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/mood"
	"github.com/RGisanEclipse/AVYO-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
)

func TestService_GetWeeklyMoodStripData(t *testing.T) {
	tz := *time.UTC
	userID := "user123"

	happy := mood.Happy
	mockResp := &model.MoodTrendResponse{
		Data: map[string]*mood.Type{
			"2026-01-10": &happy,
		},
	}

	tests := []struct {
		name      string
		req       model.MoodTrendRequest
		mockErr   *appError.Code
		wantErr   bool
		wantResp  *model.MoodTrendResponse
		wantCalls int
	}{
		{
			name: "success delegates to nova and returns response",
			req: model.MoodTrendRequest{
				UserId:   userID,
				TimeZone: tz,
			},
			mockErr:   nil,
			wantErr:   false,
			wantResp:  mockResp,
			wantCalls: 1,
		},
		{
			name: "error from nova is propagated",
			req: model.MoodTrendRequest{
				UserId:   userID,
				TimeZone: tz,
			},
			mockErr:   appError.ServerInternalError,
			wantErr:   true,
			wantResp:  nil,
			wantCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNova := &mocks.MockNovaService{
				TrendResponse: mockResp,
				TrendErr:      tt.mockErr,
			}
			svc := &service{
				nova:         mockNova,
				activityRepo: &mocks.MockActivityRepo{},
			}

			resp, err := svc.GetWeeklyMoodStripData(context.Background(), tt.req)

			if tt.wantErr {
				assert.NotNil(t, err)
				assert.Nil(t, resp)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.wantResp, resp)
			}

			assert.Len(t, mockNova.TrendCalls, tt.wantCalls)
			if tt.wantCalls > 0 {
				call := mockNova.TrendCalls[0]
				assert.Equal(t, tt.req.UserId, call.UserId)
				assert.False(t, call.StartTime.IsZero())
				assert.False(t, call.EndTime.IsZero())
				assert.True(t, call.EndTime.After(call.StartTime))
			}
		})
	}
}

func TestService_GetMonthlyTopMoodsData(t *testing.T) {
	tz := *time.UTC
	userID := "user123"

	mockResp := &model.MoodTop3Response{
		Data: []model.MoodPercentage{
			{Mood: mood.Happy, Percentage: 50},
			{Mood: mood.Worried, Percentage: 30},
			{Mood: mood.Down, Percentage: 20},
		},
	}

	tests := []struct {
		name      string
		req       model.MoodTrendRequest
		mockErr   *appError.Code
		wantErr   bool
		wantResp  *model.MoodTop3Response
		wantCalls int
		wantLimit int
	}{
		{
			name: "success delegates to nova with limit 3 and returns response",
			req: model.MoodTrendRequest{
				UserId:   userID,
				TimeZone: tz,
			},
			mockErr:   nil,
			wantErr:   false,
			wantResp:  mockResp,
			wantCalls: 1,
			wantLimit: 3,
		},
		{
			name: "error from nova is propagated",
			req: model.MoodTrendRequest{
				UserId:   userID,
				TimeZone: tz,
			},
			mockErr:   appError.ServerInternalError,
			wantErr:   true,
			wantResp:  nil,
			wantCalls: 1,
			wantLimit: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNova := &mocks.MockNovaService{
				TopResponse: mockResp,
				TopErr:      tt.mockErr,
			}
			svc := &service{
				nova:         mockNova,
				activityRepo: &mocks.MockActivityRepo{},
			}

			resp, err := svc.GetMonthlyTopMoodsData(context.Background(), tt.req)

			if tt.wantErr {
				assert.NotNil(t, err)
				assert.Nil(t, resp)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.wantResp, resp)
			}

			assert.Len(t, mockNova.TopCalls, tt.wantCalls)
			if tt.wantCalls > 0 {
				call := mockNova.TopCalls[0]
				assert.Equal(t, tt.req.UserId, call.Req.UserId)
				assert.False(t, call.Req.StartTime.IsZero())
				assert.False(t, call.Req.EndTime.IsZero())
				assert.True(t, call.Req.EndTime.After(call.Req.StartTime))
				assert.Equal(t, tt.wantLimit, call.Limit)
			}
		})
	}
}

func TestService_GetDashboardData(t *testing.T) {
	userID := "user123"
	tz := *time.UTC

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Unix()
	yesterday := time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, time.UTC).Unix()
	twoDaysAgo := time.Date(now.Year(), now.Month(), now.Day()-2, 0, 0, 0, 0, time.UTC).Unix()

	streakResp := &activityModel.StreakResponse{CurrentStreak: 3, LongestStreak: 5}

	req := model.MoodTrendRequest{UserId: userID, TimeZone: tz}

	tests := []struct {
		name              string
		existingStreak    *activityModel.Streak
		getStreakErr      error
		wantCurrentStreak int
		wantLongestStreak int
		wantStreakSaved   bool
		wantUpsertCalled  bool
	}{
		{
			name:              "new user — first dashboard load starts streak at 1",
			existingStreak:    nil,
			wantCurrentStreak: 1,
			wantLongestStreak: 1,
			wantStreakSaved:   true,
			wantUpsertCalled:  true,
		},
		{
			name: "consecutive day — streak increments",
			existingStreak: &activityModel.Streak{
				UserID:         userID,
				CurrentStreak:  4,
				LongestStreak:  7,
				LastActiveDate: yesterday,
			},
			wantCurrentStreak: 5,
			wantLongestStreak: 7,
			wantStreakSaved:   true,
			wantUpsertCalled:  true,
		},
		{
			name: "consecutive day sets new longest streak",
			existingStreak: &activityModel.Streak{
				UserID:         userID,
				CurrentStreak:  5,
				LongestStreak:  5,
				LastActiveDate: yesterday,
			},
			wantCurrentStreak: 6,
			wantLongestStreak: 6,
			wantStreakSaved:   true,
			wantUpsertCalled:  true,
		},
		{
			name: "already visited today — streak not updated again",
			existingStreak: &activityModel.Streak{
				UserID:         userID,
				CurrentStreak:  3,
				LongestStreak:  5,
				LastActiveDate: today,
			},
			wantStreakSaved:  false,
			wantUpsertCalled: true,
		},
		{
			name: "streak broken — resets to 1",
			existingStreak: &activityModel.Streak{
				UserID:         userID,
				CurrentStreak:  10,
				LongestStreak:  10,
				LastActiveDate: twoDaysAgo,
			},
			wantCurrentStreak: 1,
			wantLongestStreak: 10,
			wantStreakSaved:   true,
			wantUpsertCalled:  true,
		},
		{
			name:             "GetStreak DB error — upsert still happens, streak save skipped",
			existingStreak:   nil,
			getStreakErr:     assert.AnError,
			wantStreakSaved:  false,
			wantUpsertCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockActivity := &mocks.MockActivityRepo{
				Streak:       tt.existingStreak,
				GetStreakErr: tt.getStreakErr,
			}
			mockNova := &mocks.MockNovaService{
				StreakResponse: streakResp,
			}
			svc := &service{
				nova:         mockNova,
				activityRepo: mockActivity,
			}

			resp, _ := svc.GetDashboardData(context.Background(), req)

			assert.NotNil(t, resp)

			if tt.wantUpsertCalled {
				assert.Len(t, mockActivity.UpsertCalls, 1)
				assert.Equal(t, today, mockActivity.UpsertCalls[0])
			}

			if tt.wantStreakSaved {
				assert.NotNil(t, mockActivity.SavedStreak)
				assert.Equal(t, tt.wantCurrentStreak, mockActivity.SavedStreak.CurrentStreak)
				assert.Equal(t, tt.wantLongestStreak, mockActivity.SavedStreak.LongestStreak)
				assert.Equal(t, today, mockActivity.SavedStreak.LastActiveDate)
			} else {
				assert.Nil(t, mockActivity.SavedStreak)
			}

			// Streak data from Nova should be forwarded to response
			assert.Equal(t, streakResp, resp.Streak)
		})
	}
}
