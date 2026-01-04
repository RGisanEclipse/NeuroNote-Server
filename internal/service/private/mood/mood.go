package mood

import (
	"context"
	"strings"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	requestMiddleWare "github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	"github.com/google/uuid"
)

func (s *service) LogMood(ctx context.Context, userId string, request model.Request) (bool, *appError.Code) {

	requestId := requestMiddleWare.FromContext(ctx)
	var logFields = logger.Fields{
		"userId":    userId,
		"requestId": requestId,
	}

	var mood, reason = request.Mood, request.Reason

	var isValidMood = model.IsValidMood(mood)
	if !isValidMood {
		logger.Warn(appError.MDInvalidMood.Message, appError.MDInvalidMood, appError.MDInvalidMood, logFields)
		return false, appError.MDInvalidMood
	}

	var reasonPtr *model.ReasonType
	if strings.TrimSpace(reason) != "" {
		r := model.ReasonType(reason)
		reasonPtr = &r
	}

	entry := model.Entry{
		ID:     uuid.New().String(),
		UserID: userId,
		Mood:   model.Type(mood),
		Reason: reasonPtr,
	}

	err := s.moodRepo.SaveMood(ctx, entry)

	if err != nil {
		logFields["error"] = err.Error()
		logger.Error(appError.DBInsertFailed.Message, appError.DBInsertFailed, appError.DBInsertFailed, logFields)
		return false, appError.ServerInternalError
	}

	logger.Info("Mood Logged Successfully", logFields)

	return true, nil
}
