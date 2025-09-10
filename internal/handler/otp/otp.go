package otp

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/otp"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/user"
	models "github.com/RGisanEclipse/NeuroNote-Server/internal/models/otp"
	otpService "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	"github.com/sirupsen/logrus"
)

func RegisterOTPRoutes(router *mux.Router, svc otpService.OTPService) {
	router.HandleFunc("/api/v1/otp/request", requestOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/otp/verify", verifyOTPHandler(svc)).Methods("POST")
}

func requestOTPHandler(svc otpService.OTPService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		userId, ok := ctx.Value(user.UserIdKey).(string)
		if !ok || userId == "" {
			logger.Warn(auth.AuthError.Unauthorized, nil, logrus.Fields{
				"userId": userId,
				"requestId": reqID,
			})
			http.Error(w,auth.AuthError.Unauthorized, http.StatusUnauthorized)
			return
		}

		var req models.OTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err, logrus.Fields{
				"user": userId,
				"requestId": reqID,
				"request": req,
			})
			http.Error(w,server.ServerError.InvalidBody, http.StatusBadRequest)
			return
		}
		if !otpService.IsValidPurpose(req.Purpose) {
			logger.Warn(otp.OTPError.InvalidPurpose, nil, logrus.Fields{
				"user": userId,
				"requestId": reqID,
				"purpose": req.Purpose,
			})
			http.Error(w, otp.OTPError.InvalidPurpose, http.StatusBadRequest)
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
			logger.Warn(auth.AuthError.Unauthorized, nil, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
			})
			http.Error(w, auth.AuthError.Unauthorized, http.StatusUnauthorized)
			return
		}

		var req models.OTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
				"req": req,
			})
			http.Error(w,server.ServerError.InvalidBody, http.StatusBadRequest)
			return
		}
		if req.OTP == "" {
			logger.Warn(otp.OTPError.OTPCodeMissing, nil, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
			})
			http.Error(w, otp.OTPError.OTPCodeMissing, http.StatusBadRequest)
			return
		}
		if !otpService.IsValidPurpose(req.Purpose) {
			logger.Warn(otp.OTPError.InvalidPurpose, nil, logrus.Fields{
				"userID": userId,
				"requestId": reqID,
				"purpose": req.Purpose,
			})
			http.Error(w, otp.OTPError.InvalidPurpose, http.StatusBadRequest)
			return
		}

		resp, err := svc.VerifyOTP(ctx, userId, req.OTP, req.Purpose)
		if err != nil {
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