package onboarding

import (
	"encoding/json"
	"net/http"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	om "github.com/RGisanEclipse/NeuroNote-Server/internal/models/onboarding"
	obService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/onboarding"
	"github.com/gorilla/mux"
)

// RegisterOnboardingRoutes registers all onboarding-related routes.
func RegisterOnboardingRoutes(router *mux.Router, svc obService.Service) {
	router.HandleFunc("/api/v1/onboarding/onboard", onboardUserHandler(svc)).Methods("POST")
}

func onboardUserHandler(svc obService.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userID, ok := ctx.Value(user.UserIdKey).(string)
		if !ok || userID == "" {
			logger.Warn("User ID not found in context", nil, appError.AuthUnauthorized, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.AuthUnauthorized)
			return
		}

		var req om.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		onboardingData := om.Model{
			UserID: userID,
			Name:   req.Name,
			Age:    req.Age,
			Gender: req.Gender,
		}

		success, errCode := svc.OnboardUser(ctx, userID, onboardingData)
		if errCode != nil {
			logger.Warn(errCode.Message, nil, errCode, logger.Fields{
				"userId":    userID,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
			return
		}

		if success {
			logger.Info("User onboarded successfully", logger.Fields{
				"userId":    userID,
				"requestId": reqID,
			})
			response.WriteSuccess(w, map[string]interface{}{
				"success": true,
				"message": "User onboarded successfully",
			})
		}
	}
}
