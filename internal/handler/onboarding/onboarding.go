package onboarding

import (
	"encoding/json"
	"net/http"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	obService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/onboarding"
	"github.com/gorilla/mux"
)

// RegisterOnboardingRoutes registers all onboarding-related routes.
func RegisterOnboardingRoutes(router *mux.Router, svc obService.Service) {
	router.HandleFunc("/api/v1/onboarding", onboardUserHandler(svc)).Methods("POST")
}

func onboardUserHandler(svc obService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req om.Model
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if req.UserID == "" {
			logger.Warn("Empty userID in onboarding request", nil, appError.ServerBadRequest, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		success, errCode := svc.OnboardUser(ctx, req.UserID, req)
		if errCode != nil {
			logger.Warn(errCode.Message, nil, errCode, logger.Fields{
				"userId":    req.UserID,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
			return
		}

		if success {
			logger.Info("User onboarded successfully", logger.Fields{
				"userId":    req.UserID,
				"requestId": reqID,
			})
			response.WriteSuccess(w, map[string]interface{}{
				"success": true,
				"message": "User onboarded successfully",
			})
		}
	}
}
