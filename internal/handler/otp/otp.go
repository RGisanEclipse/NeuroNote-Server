package otp

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/sirupsen/logrus"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	models "github.com/RGisanEclipse/NeuroNote-Server/internal/models/otp"
	otpService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
)

func RegisterOTPRoutes(router *mux.Router, svc otpService.OTPService) {
	router.HandleFunc("/auth/otp/request", requestOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/auth/otp/verify", verifyOTPHandler(svc)).Methods("POST")
}

func requestOTPHandler(svc otpService.OTPService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)
		if !ok || userId == "" {
			logger.Error("OTP unauthorised request", nil, logrus.Fields{
				"userId": userId,
				"requestId": reqID,
			})
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req models.OTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Error("OTP invalid request", err, logrus.Fields{
				"user": userId,
				"requestId": reqID,
			})
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !otpService.IsValidPurpose(req.Purpose) {
			logger.Error("Invalid Purpose for OTP", err, logrus.Fields{
				"user": userId,
				"requestId": reqID,
			})
			http.Error(w, "invalid purpose", http.StatusBadRequest)
			return
		}

		resp, err := svc.RequestOTP(ctx, userId, req.Purpose)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logger.Info("Response from request OTP handler", logrus.Fields{
			"user": userId,
			"requestId": reqID,
			"success": resp.Success,
			"message": resp.Message,
		})
		response.WriteJSON(w, http.StatusOK, resp)
	}
}

func verifyOTPHandler(svc otpService.OTPService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)
		if !ok || userId == "" {
			logger.Error("unauthorised request for OTP verification", nil, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
			})
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req models.OTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Error("verify OTP invalid request", err, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
			})
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.OTP == "" {
			logger.Error("verify OTP empty code received", nil, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
			})
			http.Error(w, "code is required", http.StatusBadRequest)
			return
		}
		if !otpService.IsValidPurpose(req.Purpose) {
			logger.Error("verify OTP invalid Purpose", nil, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
				"purpose": req.Purpose,
			})
			http.Error(w, "invalid purpose", http.StatusBadRequest)
			return
		}

		resp, err := svc.VerifyOTP(ctx, userId, req.OTP, req.Purpose)
		if err != nil {
			logger.Error("OTP verification failed", err, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
			})
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		logger.Info("Response from verify OTP handler", logrus.Fields{
			"user": userId,
			"requestId": reqID,
			"success": resp.Success,
			"message": resp.Message,
		})
		response.WriteJSON(w, http.StatusOK, resp)
	}
}