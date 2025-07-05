package rate

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models"
)

var (
	clients = make(map[string]*client) 
	mu      sync.Mutex
)

// Cleanup
func init() {
	go func() {
		for {
			time.Sleep(time.Hour)
			mu.Lock()
			clients = make(map[string]*client) 
			mu.Unlock()
		}
	}()
}

func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		route := r.URL.Path
		limit, ok := routeLimits[route]
		if !ok { // un-limited route
			next.ServeHTTP(w, r)
			return
		}

		key := ip + route

		mu.Lock()
		cl, exists := clients[key]
		now := time.Now()

		if !exists || now.Sub(cl.windowStart) >= time.Minute {
			cl = &client{requests: 1, windowStart: now}
			clients[key] = cl
		} else {
			cl.requests++
		}

		exceeded := cl.requests > limit
		mu.Unlock()

		if exceeded {
			logger.Warn(
				server.ServerError.TooManyRequests,
				errors.New("rate limit exceeded"),
				logrus.Fields{"ip": ip, "route": route},
			)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(models.RateLimitResponse{
				Success: false,
				Message: server.ServerError.TooManyRequests,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}