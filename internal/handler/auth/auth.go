package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/common/response"
	authErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/auth"
	otpErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/otp"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	authmodel "github.com/RGisanEclipse/NeuroNote-Server/internal/models/auth"
	authservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
)

func RegisterAuthRoutes(router *mux.Router, svc authservice.AuthService) {
	router.HandleFunc("/api/v1/auth/signup", signupHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signin", signinHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signup/otp", signupOTPHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/signup/otp/verify", signupOTPVerifyHandler(svc)).Methods("POST")
	router.HandleFunc("/api/v1/auth/token/refresh", refreshTokenHandler(svc)).Methods("POST")
}


func signupHandler(svc authservice.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err)
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: server.ServerError.BadRequest,
			})
			return
		}
		if err := req.Validate(); err != nil {
			logger.Warn(server.ServerError.BadRequest, err, logrus.Fields{
				"email": req.Email,
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}
		
		res, err := svc.Signup(ctx, req.Email, req.Password)
		if err != nil {
			logger.Warn("Signup failed", err, logrus.Fields{
				"email": req.Email,
				"requestId": reqID,
			})
			
			var statusCode int
			if err.Error() == authErr.AuthError.EmailExists {
				statusCode = http.StatusBadRequest
			} else {
				statusCode = http.StatusInternalServerError
			}
			
			response.WriteJSON(w, statusCode, authmodel.AuthResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}
		logger.Info("Response from signup handler", logrus.Fields{
			"email": req.Email,
			"requestId": reqID,
			"success": res.Success,
			"message": res.Message, 
			"isVerified": res.IsVerified,
		})

		http.SetCookie(w, &http.Cookie{
            Name:     "refreshToken",
            Value:    res.RefreshToken,
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
            Path:     "/",
            MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
        })

		response.WriteJSON(w, http.StatusOK, authmodel.AuthResponse{
			Success: res.Success,
			Message: res.Message,
			AccessToken:   res.AccessToken,
			IsVerified: res.IsVerified,
		})
	}
}

func signinHandler(svc authservice.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err)
			response.WriteJSON(w, http.StatusBadRequest, authmodel.AuthResponse{
				Success: false,
				Message: server.ServerError.BadRequest,
			})
			return
		}

		res, err := svc.Signin(ctx, req.Email, req.Password)
		if err != nil {
			logger.Warn("Signin failed", err, logrus.Fields{
				"email": req.Email,
				"requestId": reqID,
			})
			
			var statusCode int
			if err.Error() == authErr.AuthError.IncorrectPassword || err.Error() == authErr.AuthError.EmailDoesntExist {
				statusCode = http.StatusUnauthorized
			} else {
				statusCode = http.StatusInternalServerError
			}
			
			response.WriteJSON(w, statusCode, authmodel.AuthResponse{
				Success: false,
				Message: err.Error(),
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
            Name:     "refreshToken",
            Value:    res.RefreshToken,
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
            Path:     "/",
            MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
        })

		response.WriteJSON(w, http.StatusOK, authmodel.AuthResponse{
			Success: res.Success,
			Message: res.Message,
			AccessToken:  res.AccessToken,
			IsVerified: res.IsVerified,
		})
	}
}

func refreshTokenHandler(svc authservice.AuthService) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqID := request.FromContext(ctx)
		var req authmodel.RefreshTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn(server.ServerError.InvalidBody, err, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusBadRequest, authmodel.RefreshTokenResponse{
				AccessToken:  "",
			})
			return
		}

		if req.RefreshToken == "" {
			logger.Warn("Empty refresh token in request", nil, logrus.Fields{
				"requestId": reqID,
			})
			response.WriteJSON(w, http.StatusBadRequest, authmodel.RefreshTokenResponse{
				AccessToken:  "",
			})
			return
		}

		res, err := svc.RefreshToken(ctx, req.RefreshToken)
		if err != nil{
			logger.Warn("Refresh token failed", err, logrus.Fields{
				"refreshToken": req.RefreshToken,
				"requestId": reqID,
			})
			
			var statusCode int
			if err.Error() == authErr.AuthError.InvalidRefreshToken || err.Error() == authErr.AuthError.RefreshTokenMismatch {
				statusCode = http.StatusUnauthorized
			} else {
				statusCode = http.StatusInternalServerError
			}
			
			response.WriteJSON(w, statusCode, authmodel.RefreshTokenResponse{
				AccessToken:  "",
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
            Name:     "refreshToken",
            Value:    res.RefreshToken,
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
            Path:     "/",
            MaxAge:   int(authservice.RefreshTokenExpiry.Seconds()),
        })

		response.WriteJSON(w, http.StatusOK, authmodel.RefreshTokenResponse{
			AccessToken:  res.AccessToken,
		})
	}
}

func signupOTPHandler(svc authservice.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        reqID := request.FromContext(ctx)

        var req authmodel.SignupOTPRequest

        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            logger.Warn(server.ServerError.InvalidBody, err, logrus.Fields{
                "requestId": reqID,
            })
            response.WriteJSON(w, http.StatusBadRequest, authmodel.SignupOTPResponse{
                Success: false,
                Message: server.ServerError.BadRequest,
            })
            return
        }

        if req.UserId == "" {
            logger.Warn("Empty userId in OTP request", nil, logrus.Fields{
                "requestId": reqID,
            })
            response.WriteJSON(w, http.StatusBadRequest, authmodel.SignupOTPResponse{
                Success: false,
                Message: server.ServerError.BadRequest,
            })
            return
        }

		res, err := svc.SignupOTP(ctx, req.UserId)
        if err != nil {
            logger.Warn("Signup OTP Failed", err, logrus.Fields{
                "userId":    req.UserId,
                "requestId": reqID,
            })
            response.WriteJSON(w, http.StatusInternalServerError, authmodel.SignupOTPResponse{
                Success: false,
                Message: server.ServerError.InternalError,
            })
            return 
        }

        response.WriteJSON(w, http.StatusOK, res)
    }
}

func signupOTPVerifyHandler(svc authservice.AuthService) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        reqID := request.FromContext(ctx)

        var req authmodel.SignupOTPVerifyRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            logger.Warn(server.ServerError.InvalidBody, err, logrus.Fields{
                "requestId": reqID,
            })
            response.WriteJSON(w, http.StatusBadRequest, authmodel.SignupOTPResponse{
                Success: false,
                Message: server.ServerError.BadRequest,
            })
            return
        }

        if req.UserId == "" || req.Code == "" {
            logger.Warn("Empty userId or code in OTP verify request", nil, logrus.Fields{
                "requestId": reqID,
            })
            response.WriteJSON(w, http.StatusBadRequest, authmodel.SignupOTPResponse{
                Success: false,
                Message: server.ServerError.BadRequest,
            })
            return
        }

        res, err := svc.SignupOTPVerify(ctx, req.UserId, req.Code)
        if err != nil {
            logger.Warn("Signup OTP Verification Failed", err, logrus.Fields{
                "userId":    req.UserId,
                "requestId": reqID,
            })

            var statusCode int
            var message string

            switch err.Error() {
            case otpErr.OTPError.InvalidOTP:
                statusCode = http.StatusBadRequest
                message = otpErr.OTPError.InvalidOTP
            case otpErr.OTPError.OTPExpiredOrNotFound:
                statusCode = http.StatusBadRequest
                message = otpErr.OTPError.OTPExpiredOrNotFound
            default:
                statusCode = http.StatusInternalServerError
                message = server.ServerError.InternalError
            }

            response.WriteJSON(w, statusCode, authmodel.SignupOTPResponse{
                Success: false,
                Message: message,
            })
            return
        }

        response.WriteJSON(w, http.StatusOK, res)
    }
}