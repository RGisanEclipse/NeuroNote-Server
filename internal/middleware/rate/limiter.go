package rate

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models"
)

const rateLimitWindow = time.Minute

func Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		route := r.URL.Path
		limit, ok := routeLimits[route]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		var key string
		if userID, ok := r.Context().Value("userID").(string); ok && userID != "" {
			key = "rate:user:" + userID + ":" + route
		} else {
			key = "rate:ip:" + ip + ":" + route
		}

		count, err := redis.Client.Incr(r.Context(), key).Result()
		if err != nil {
			logger.Error("RateLimit Redis INCR failed", err, nil)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if count == 1 {
			_, err := redis.Client.Expire(r.Context(), key, rateLimitWindow).Result()
			if err != nil {
				logger.Error(server.Error.TooManyRequests, err, nil)
			}
		}

		if count > int64(limit) {
			logger.Warn(
				server.Error.TooManyRequests,
				errors.New(server.Error.TooManyRequests),
				logrus.Fields{"ip": ip, "route": route, "key": key},
			)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(models.RateLimitResponse{
				Success: false,
				Message: server.Error.TooManyRequests,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
