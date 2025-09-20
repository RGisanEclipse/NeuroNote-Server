package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
)

// setRefreshTokenCookie sets a refresh token cookie with secure settings
func setRefreshTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
	})
}

func RegisterAuthRoutes(router *mux.Router, svc authservice.S) {
	router.HandleFunc("/api/v1/auth/signup", signupHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signin", signinHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signup/otp", signupOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signup/otp/verify", signupOTPVerifyHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/token/refresh", refreshTokenHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/password/otp", forgotPasswordOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/password/otp/verify", forgotPasswordOTPVerifyHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/password/reset", passwordResetHandler(svc)).Methods("POST")
}

func signupHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody)
			response.WriteError(w, error.ServerBadRequest)
			return
		}
		if err := req.Validate(); err != nil {
			logger.Warn(error.ServerBadRequest.Message, err, error.ServerBadRequest, logger.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.Signup(ctx, req.Email, req.Password)
		if err != nil {
			logger.Warn(error.AuthSignupFailed.Message, err, error.AuthSignupFailed, logrus.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})

			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from signup handler", logrus.Fields{
			"email":      req.Email,
			"requestId":  reqID,
			"success":    res.Success,
			"message":    res.Message,
			"isVerified": res.IsVerified,
		})

		setRefreshTokenCookie(w, res.RefreshToken)

		response.WriteSuccess(w, map[string]interface{}{
			"token":      res.AccessToken,
			"isVerified": res.IsVerified,
		}, res.Message)
	}
}

func signinHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody)
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.Signin(ctx, req.Email, req.Password)
		if err != nil {
			logger.Warn(error.AuthSigninFailed.Message, err, error.AuthSigninFailed, logrus.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})

			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from signin handler", logrus.Fields{
			"email":      req.Email,
			"requestId":  reqID,
			"success":    res.Success,
			"message":    res.Message,
			"isVerified": res.IsVerified,
		})

		setRefreshTokenCookie(w, res.RefreshToken)

		response.WriteSuccess(w, map[string]interface{}{
			"token":      res.AccessToken,
			"isVerified": res.IsVerified,
		}, res.Message)
	}
}

func refreshTokenHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		if req.RefreshToken == "" {
			logger.Warn(error.ServerBadRequest.Message, nil, error.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.RefreshToken(ctx, req.RefreshToken)
		if err != nil {
			logger.Warn("Refresh token failed", err, error.ServerInternalError, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from refresh token handler", logrus.Fields{
			"requestId": reqID,
		})

		setRefreshTokenCookie(w, res.RefreshToken)

		response.WriteSuccess(w, map[string]interface{}{
			"accessToken": res.AccessToken,
		})
	}
}

func signupOTPHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.SignupOTPRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		if req.UserId == "" {
			logger.Warn("Empty userId in OTP request", nil, error.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.SignupOTP(ctx, req.UserId)
		if err != nil {
			logger.Warn("Signup OTP failed", err, error.ServerInternalError, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from signup OTP handler", logrus.Fields{
			"userId":    req.UserId,
			"requestId": reqID,
			"success":   res.Success,
			"message":   res.Message,
		})

		response.WriteSuccess(w, res)
	}
}

func signupOTPVerifyHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.OTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		if req.UserId == "" || req.Code == "" {
			logger.Warn("Empty userId or code in OTP verify request", nil, error.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.SignupOTPVerify(ctx, req.UserId, req.Code)
		if err != nil {
			logger.Warn("Signup OTP verify failed", err, error.ServerInternalError, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from signup OTP verify handler", logrus.Fields{
			"userId":    req.UserId,
			"requestId": reqID,
			"success":   res.Success,
			"message":   res.Message,
		})

		response.WriteSuccess(w, res)
	}
}

func forgotPasswordOTPHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.ForgotPasswordOTPRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		if req.Email == "" {
			logger.Warn("Empty email in OTP request", nil, error.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.ForgotPasswordOTP(ctx, req.Email)
		if err != nil {
			logger.Warn("OTP Request Failed", err, error.ServerInternalError, logrus.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from forgot password OTP handler", logrus.Fields{
			"email":     req.Email,
			"requestId": reqID,
			"success":   res.Success,
			"message":   res.Message,
		})

		response.WriteSuccess(w, res)
	}
}

func forgotPasswordOTPVerifyHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.OTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		if req.UserId == "" || req.Code == "" {
			logger.Warn("Empty userId or code in OTP verify request", nil, error.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.ForgotPasswordOTPVerify(ctx, req.UserId, req.Code)
		if err != nil {
			logger.Warn("Forgot password OTP verify failed", err, error.ServerInternalError, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from forgot password OTP verify handler", logrus.Fields{
			"userId":    req.UserId,
			"requestId": reqID,
			"success":   res.Success,
			"message":   res.Message,
		})

		response.WriteSuccess(w, res)
	}
}

func passwordResetHandler(svc authservice.S) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(error.ServerInvalidBody.Message, err, error.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		req.UserId = strings.TrimSpace(req.UserId)

		if req.UserId == "" || len(req.UserId) != 14 {
			logger.Warn("Invalid userId in password reset request", nil, error.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
				"userId":    req.UserId,
			})
			response.WriteError(w, error.ServerBadRequest)
			return
		}

		res, err := svc.ResetPassword(ctx, req.UserId, req.Password)
		if err != nil {
			logger.Warn("Password reset failed", err, error.ServerInternalError, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, error.ServerInternalError)
			return
		}
		logger.Info("Response from password reset handler", logrus.Fields{
			"userId":    req.UserId,
			"requestId": reqID,
			"success":   res.Success,
			"message":   res.Message,
		})

		response.WriteSuccess(w, res)
	}
}
