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

		data, errCode := svc.GetWeeklyMoodStripData(ctx, req)
		if errCode != nil {
			logger.Warn(errCode.Message, nil, errCode, logFields)
			response.WriteError(w, errCode)
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

		data, errCode := svc.GetMonthlyTopMoodsData(ctx, req)
		if errCode != nil {
			logger.Warn(errCode.Message, nil, errCode, logFields)
			response.WriteError(w, errCode)
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

		data, _ := svc.GetDashboardData(ctx, req)
		response.WriteSuccess(w, map[string]interface{}{
			"weeklyMoodStrip": data.WeeklyMoodStrip,
			"monthlyTopMoods": data.MonthlyTopMoods,
		})
	}
}
