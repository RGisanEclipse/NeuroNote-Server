package atlas

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
				nova: mockNova,
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
				nova: mockNova,
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
