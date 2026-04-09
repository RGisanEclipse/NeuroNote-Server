package atlas

import (
	"context"
	"encoding/json"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	requestMiddleWare "github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	moodModel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	syncModel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/sync"
	moodService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/mood"
)

// BulkSync processes a batch of offline operations, returning per-operation results.
// Each operation succeeds or fails independently — a single failure never blocks others.
func (s *service) BulkSync(ctx context.Context, userID string, req syncModel.SyncRequest) *syncModel.SyncResponse {
	results := make([]syncModel.OperationResult, len(req.Operations))
	failed := 0

	requestId := requestMiddleWare.FromContext(ctx)
	logFields := logger.Fields{
		"userId":    userID,
		"requestId": requestId,
		"total":     len(req.Operations),
	}

	logger.Info("Bulk sync started", logFields)

	for i, op := range req.Operations {
		result := syncModel.OperationResult{Index: i}
		opFields := logger.Fields{
			"userId":    userID,
			"requestId": requestId,
			"index":     i,
			"type":      op.Type,
		}

		handler, ok := s.handlers[op.Type]
		if !ok {
			logger.Warn(appError.SyncUnknownType.Message, nil, appError.SyncUnknownType, opFields)
			result.Success = false
			result.Error = appError.SyncUnknownType.Message
			failed++
			results[i] = result
			continue
		}

		if errCode := handler.Process(ctx, userID, op.Payload); errCode != nil {
			logger.Warn("Sync operation failed", nil, errCode, opFields)
			result.Success = false
			result.Error = errCode.Message
			failed++
		} else {
			result.Success = true
		}
		results[i] = result
	}

	logger.Info("Bulk sync completed", logger.Fields{
		"userId":    userID,
		"requestId": requestId,
		"total":     len(req.Operations),
		"failed":    failed,
	})

	return &syncModel.SyncResponse{
		Results:   results,
		Processed: len(req.Operations),
		Failed:    failed,
	}
}

// moodHandler handles offline mood log operations.
type moodHandler struct {
	moodSvc moodService.Service
}

type moodPayload struct {
	Mood      string `json:"mood"`
	Reason    string `json:"reason,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

func (h *moodHandler) Process(ctx context.Context, userID string, payload json.RawMessage) *appError.Code {
	var p moodPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		logger.Warn(appError.SyncInvalidPayload.Message, err, appError.SyncInvalidPayload, logger.Fields{
			"userId":    userID,
			"requestId": requestMiddleWare.FromContext(ctx),
		})
		return appError.SyncInvalidPayload
	}

	_, errCode := h.moodSvc.LogMood(ctx, userID, moodModel.Request{
		Mood:      p.Mood,
		Reason:    p.Reason,
		Timestamp: p.Timestamp,
	})
	return errCode
}
