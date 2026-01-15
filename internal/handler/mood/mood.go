package mood

import (
	"encoding/json"
	"net/http"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
	moodService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/mood"
	"github.com/gorilla/mux"
)

// RegisterMoodRoutes registers all mood-related routes.
func RegisterMoodRoutes(router *mux.Router, svc moodService.Service) {
	router.HandleFunc("/api/v1/mood", moodLogHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/mood/entries", getMoodHandler(svc)).Methods("POST")
}

func moodLogHandler(svc moodService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)

		var logFields = logger.Fields{
			"userId":    userId,
			"requestId": reqID,
		}

		if !ok || userId == "" {
			logger.Warn("User ID not found in context", nil, appError.AuthUnauthorized, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.AuthUnauthorized)
			return
		}

		var req model.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logFields)
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		success, err := svc.LogMood(ctx, userId, req)
		if err != nil {
			logger.Warn(err.Message, nil, err, logFields)
			response.WriteError(w, err)
			return
		}

		if success {
			logger.Info("Mood logged successfully", logFields)

			response.WriteSuccess(w, map[string]interface{}{
				"success": success,
				"message": "Mood logged successfully",
			})
		}
	}
}
func getMoodHandler(svc moodService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)

		var logFields = logger.Fields{
			"userId":    userId,
			"requestId": reqID,
		}

		if !ok || userId == "" {
			logger.Warn("User ID not found in context", nil, appError.AuthUnauthorized, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.AuthUnauthorized)
			return
		}

		var req model.RequestEntry

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logFields)
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		data, svcErr := svc.GetMood(ctx, userId, req.Days)
		if svcErr != nil {
			logger.Warn(svcErr.Message, nil, svcErr, logFields)
			response.WriteError(w, svcErr)
			return
		}

		logger.Info("Mood entry fetch successful", logFields)

		response.WriteSuccess(w, map[string]interface{}{
			"data": data,
		})
	}
}
