package atlas

import (
	"net/http"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	atlasService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/atlas"
	"github.com/gorilla/mux"
)

// RegisterDashboardRoutes registers all dashboard-related routes.
func RegisterDashboardRoutes(router *mux.Router, svc atlasService.Service) {
	router.HandleFunc("/api/v1/mood/weekly/mood-strip", weeklyMoodStripHandler(svc)).Methods("GET")
	router.HandleFunc("/api/v1/mood/monthly/top-moods", monthlyTopMoodsHandler(svc)).Methods("GET")
	router.HandleFunc("/api/v1/dashboard", dashboardAPIHandler(svc)).Methods("GET")
}

func weeklyMoodStripHandler(svc atlasService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)

		logFields := logger.Fields{
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

		req := model.MoodTrendRequest{
			UserId:   userId,
			TimeZone: *time.UTC,
		}

		data, svcErr := svc.GetWeeklyMoodStripData(ctx, req)
		if svcErr != nil {
			if appErr, ok := svcErr.(*appError.Code); ok {
				logger.Warn(appErr.Message, nil, appErr, logFields)
				response.WriteError(w, appErr)
				return
			}
			logger.Error(appError.ServerInternalError.Message, svcErr, appError.ServerInternalError, logFields)
			response.WriteError(w, appError.ServerInternalError)
			return
		}

		logger.Info("Weekly mood strip fetched successfully", logFields)
		response.WriteSuccess(w, map[string]interface{}{
			"data": data.Data,
		})
	}
}

func monthlyTopMoodsHandler(svc atlasService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)

		logFields := logger.Fields{
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

		req := model.MoodTrendRequest{
			UserId:   userId,
			TimeZone: *time.UTC,
		}

		data, svcErr := svc.GetMonthlyTopMoodsData(ctx, req)
		if svcErr != nil {
			if appErr, ok := svcErr.(*appError.Code); ok {
				logger.Warn(appErr.Message, nil, appErr, logFields)
				response.WriteError(w, appErr)
				return
			}
			logger.Error(appError.ServerInternalError.Message, svcErr, appError.ServerInternalError, logFields)
			response.WriteError(w, appError.ServerInternalError)
			return
		}

		logger.Info("Monthly top 3 moods fetched successfully", logFields)
		response.WriteSuccess(w, map[string]interface{}{
			"data": data.Data,
		})
	}
}

func dashboardAPIHandler(svc atlasService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)

		logFields := logger.Fields{
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

		req := model.MoodTrendRequest{
			UserId:   userId,
			TimeZone: *time.UTC,
		}

		weekly, weeklyErr := svc.GetWeeklyMoodStripData(ctx, req)
		if weeklyErr != nil {
			if appErr, ok := weeklyErr.(*appError.Code); ok {
				logger.Warn(appErr.Message, nil, appErr, logFields)
				response.WriteError(w, appErr)
				return
			}
			logger.Error(appError.ServerInternalError.Message, weeklyErr, appError.ServerInternalError, logFields)
			response.WriteError(w, appError.ServerInternalError)
			return
		}

		monthly, monthlyErr := svc.GetMonthlyTopMoodsData(ctx, req)
		if monthlyErr != nil {
			if appErr, ok := monthlyErr.(*appError.Code); ok {
				logger.Warn(appErr.Message, nil, appErr, logFields)
				response.WriteError(w, appErr)
				return
			}
			logger.Error(appError.ServerInternalError.Message, monthlyErr, appError.ServerInternalError, logFields)
			response.WriteError(w, appError.ServerInternalError)
			return
		}

		logger.Info("Dashboard data fetched successfully", logFields)
		response.WriteSuccess(w, map[string]interface{}{
			"weeklyMoodStrip": weekly.Data,
			"monthlyTopMoods": monthly.Data,
		})
	}
}
