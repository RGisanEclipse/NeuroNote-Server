package atlas

import (
	"context"
	"encoding/json"
	"testing"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	syncModel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/sync"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/test/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func moodOp(mood, reason string, timestamp int64) syncModel.Operation {
	p, _ := json.Marshal(map[string]any{
		"mood":      mood,
		"reason":    reason,
		"timestamp": timestamp,
	})
	return syncModel.Operation{Type: "mood", Payload: p}
}

func TestService_BulkSync(t *testing.T) {
	userID := "user123"

	tests := []struct {
		name         string
		operations   []syncModel.Operation
		setupMock    func(*mocks.MockMoodService)
		wantTotal    int
		wantFailed   int
		wantResults  []syncModel.OperationResult
	}{
		{
			name: "all operations succeed",
			operations: []syncModel.Operation{
				moodOp("happy", "achievement", 1700000000),
				moodOp("worried", "workDeadlines", 1700086400),
				moodOp("down", "loneliness", 1700172800),
			},
			setupMock: func(m *mocks.MockMoodService) {
				m.On("LogMood", mock.Anything, userID, mock.Anything).
					Return(true, (*appError.Code)(nil)).Times(3)
			},
			wantTotal:  3,
			wantFailed: 0,
			wantResults: []syncModel.OperationResult{
				{Index: 0, Success: true},
				{Index: 1, Success: true},
				{Index: 2, Success: true},
			},
		},
		{
			name: "partial failure — one invalid mood",
			operations: []syncModel.Operation{
				moodOp("happy", "achievement", 1700000000),
				moodOp("notamood", "", 1700086400),
				moodOp("down", "loneliness", 1700172800),
			},
			setupMock: func(m *mocks.MockMoodService) {
				m.On("LogMood", mock.Anything, userID, mock.MatchedBy(func(r any) bool { return true })).
					Return(true, (*appError.Code)(nil)).Once()
				m.On("LogMood", mock.Anything, userID, mock.MatchedBy(func(r any) bool { return true })).
					Return(false, appError.MDInvalidMood).Once()
				m.On("LogMood", mock.Anything, userID, mock.MatchedBy(func(r any) bool { return true })).
					Return(true, (*appError.Code)(nil)).Once()
			},
			wantTotal:  3,
			wantFailed: 1,
			wantResults: []syncModel.OperationResult{
				{Index: 0, Success: true},
				{Index: 1, Success: false, Error: appError.MDInvalidMood.Message},
				{Index: 2, Success: true},
			},
		},
		{
			name: "unknown operation type fails gracefully",
			operations: []syncModel.Operation{
				{Type: "note", Payload: json.RawMessage(`{"content":"hello"}`)},
				moodOp("happy", "", 1700000000),
			},
			setupMock: func(m *mocks.MockMoodService) {
				m.On("LogMood", mock.Anything, userID, mock.Anything).
					Return(true, (*appError.Code)(nil)).Once()
			},
			wantTotal:  2,
			wantFailed: 1,
			wantResults: []syncModel.OperationResult{
				{Index: 0, Success: false, Error: appError.SyncUnknownType.Message},
				{Index: 1, Success: true},
			},
		},
		{
			name: "invalid JSON payload fails that operation",
			operations: []syncModel.Operation{
				{Type: "mood", Payload: json.RawMessage(`{invalid`)},
				moodOp("happy", "", 1700000000),
			},
			setupMock: func(m *mocks.MockMoodService) {
				m.On("LogMood", mock.Anything, userID, mock.Anything).
					Return(true, (*appError.Code)(nil)).Once()
			},
			wantTotal:  2,
			wantFailed: 1,
			wantResults: []syncModel.OperationResult{
				{Index: 0, Success: false, Error: appError.SyncInvalidPayload.Message},
				{Index: 1, Success: true},
			},
		},
		{
			name:       "empty operations returns zero results",
			operations: []syncModel.Operation{},
			setupMock:  func(m *mocks.MockMoodService) {},
			wantTotal:  0,
			wantFailed: 0,
			wantResults: []syncModel.OperationResult{},
		},
		{
			name: "all operations fail — db error",
			operations: []syncModel.Operation{
				moodOp("happy", "", 1700000000),
				moodOp("down", "", 1700086400),
			},
			setupMock: func(m *mocks.MockMoodService) {
				m.On("LogMood", mock.Anything, userID, mock.Anything).
					Return(false, appError.ServerInternalError).Times(2)
			},
			wantTotal:  2,
			wantFailed: 2,
			wantResults: []syncModel.OperationResult{
				{Index: 0, Success: false, Error: appError.ServerInternalError.Message},
				{Index: 1, Success: false, Error: appError.ServerInternalError.Message},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMoodSvc := new(mocks.MockMoodService)
			tt.setupMock(mockMoodSvc)

			svc := &service{
				nova:         &mocks.MockNovaService{},
				activityRepo: &mocks.MockActivityRepo{},
				handlers: map[string]OperationHandler{
					"mood": &moodHandler{moodSvc: mockMoodSvc},
				},
			}

			resp := svc.BulkSync(context.Background(), userID, syncModel.SyncRequest{
				Operations: tt.operations,
			})

			assert.Equal(t, tt.wantTotal, resp.Processed)
			assert.Equal(t, tt.wantFailed, resp.Failed)
			assert.Equal(t, tt.wantResults, resp.Results)

			mockMoodSvc.AssertExpectations(t)
		})
	}
}
