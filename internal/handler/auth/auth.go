package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
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

// setUserIdCookie sets a user ID cookie with secure settings
func setUserIdCookie(w http.ResponseWriter, userId string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "userId",
		Value:    userId,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   86400 * 30, // 30 days
	})
}

func RegisterAuthRoutes(router *mux.Router, svc *authservice.Service) {
	// Auth flows
	registerSignupRoutes(router, svc.Signup)
	registerSigninRoutes(router, svc.Signin)
	registerForgotPasswordRoutes(router, svc.ForgotPassword)
}

func registerSignupRoutes(router *mux.Router, svc authservice.SignupService) {
	router.HandleFunc("/api/v1/auth/signup", signupHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signup/otp", signupOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signup/otp/verify", signupOTPVerifyHandler(svc)).Methods("POST")
}

func registerSigninRoutes(router *mux.Router, svc authservice.SigninService) {
	router.HandleFunc("/api/v1/auth/signin", signinHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/token/refresh", refreshTokenHandler(svc)).Methods("POST")
}

func registerForgotPasswordRoutes(router *mux.Router, svc authservice.ForgotPasswordService) {
	router.HandleFunc("/api/v1/auth/password/otp", forgotPasswordOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/password/otp/verify", forgotPasswordOTPVerifyHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/password/reset", passwordResetHandler(svc)).Methods("POST")
}

func signupHandler(svc authservice.SignupService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody)
			response.WriteError(w, appError.ServerBadRequest)
			return
		}
		if err := req.Validate(); err != nil {
			// Cast the error to *appError.Code since Validate() returns specific error codes
			var errCode *appError.Code
			if errors.As(err, &errCode) {
				logger.Warn(errCode.Message, nil, errCode, logger.Fields{
					"email":     req.Email,
					"requestId": reqID,
				})
				response.WriteError(w, errCode)
			}
			return
		}

		res, errCode := svc.Signup(ctx, req.Email, req.Password)
		if errCode != nil {
			logger.Warn(errCode.Message, nil, errCode, logrus.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})

			response.WriteError(w, errCode)
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

func signinHandler(svc authservice.SigninService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody)
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if err := req.Validate(); err != nil {
			var errCode *appError.Code
			if errors.As(err, &errCode) {
				logger.Warn(errCode.Message, nil, errCode, logger.Fields{
					"email":     req.Email,
					"requestId": reqID,
				})
				response.WriteError(w, errCode)
			}
			return
		}

		res, errCode := svc.Signin(ctx, req.Email, req.Password)
		if errCode != nil {
			logger.Warn(errCode.Message, nil, errCode, logrus.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})

			response.WriteError(w, errCode)
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

func refreshTokenHandler(svc authservice.SigninService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if req.RefreshToken == "" {
			logger.Warn(appError.ServerBadRequest.Message, nil, appError.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		res, errCode := svc.RefreshToken(ctx, req.RefreshToken)
		if errCode != nil {
			logger.Warn("Refresh token failed", nil, errCode, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
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

func signupOTPHandler(svc authservice.SignupService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.SignupOTPRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if req.UserId == "" {
			logger.Warn("Empty userId in OTP request", nil, appError.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		res, errCode := svc.SignupOTP(ctx, req.UserId)
		if errCode != nil {
			logger.Warn("Signup OTP failed", nil, errCode, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
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

func signupOTPVerifyHandler(svc authservice.SignupService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.OTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if req.UserId == "" || req.Code == "" {
			logger.Warn("Empty userId or code in OTP verify request", nil, appError.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		res, errCode := svc.SignupOTPVerify(ctx, req.UserId, req.Code)
		if errCode != nil {
			logger.Warn("Signup OTP verify failed", nil, errCode, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
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

func forgotPasswordOTPHandler(svc authservice.ForgotPasswordService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.ForgotPasswordOTPRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if req.Email == "" {
			logger.Warn("Empty email in OTP request", nil, appError.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		res, errCode := svc.ForgotPasswordOTP(ctx, req.Email)
		if errCode != nil {
			logger.Warn("OTP Request Failed", nil, errCode, logrus.Fields{
				"email":     req.Email,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
			return
		}
		logger.Info("Response from forgot password OTP handler", logrus.Fields{
			"email":     req.Email,
			"requestId": reqID,
			"success":   res.Success,
			"message":   res.Message,
		})

		if res.Success && res.UserId != "" {
			setUserIdCookie(w, res.UserId)
		}

		genericResponse := authmodel.GenericOTPResponse{
			Success: res.Success,
			Message: res.Message,
		}

		response.WriteSuccess(w, genericResponse)
	}
}

func forgotPasswordOTPVerifyHandler(svc authservice.ForgotPasswordService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.OTPVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		if req.UserId == "" || req.Code == "" {
			logger.Warn("Empty userId or code in OTP verify request", nil, appError.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		res, errCode := svc.ForgotPasswordOTPVerify(ctx, req.UserId, req.Code)
		if errCode != nil {
			logger.Warn("Forgot password OTP verify failed", nil, errCode, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
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

func passwordResetHandler(svc authservice.ForgotPasswordService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)

		var req authmodel.ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(appError.ServerInvalidBody.Message, err, appError.ServerInvalidBody, logger.Fields{
				"requestId": reqID,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		req.UserId = strings.TrimSpace(req.UserId)

		if req.UserId == "" || len(req.UserId) != 14 {
			logger.Warn("Invalid userId in password reset request", nil, appError.ServerBadRequest, logrus.Fields{
				"requestId": reqID,
				"userId":    req.UserId,
			})
			response.WriteError(w, appError.ServerBadRequest)
			return
		}

		res, errCode := svc.ResetPassword(ctx, req.UserId, req.Password)
		if errCode != nil {
			logger.Warn("Password reset failed", nil, errCode, logrus.Fields{
				"userId":    req.UserId,
				"requestId": reqID,
			})
			response.WriteError(w, errCode)
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
