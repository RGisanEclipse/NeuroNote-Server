package middleware

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models"
)

// config for each public route
var routeLimits = map[string]rate.Limit{
	"/signup": 3, // 3 requests per minute
	"/signin": 5, // 5 requests per minute
}

// storage of limiters per IP
type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	clients = make(map[string]*client)
	mu      sync.Mutex
)

// Init starts a goroutine to clean up old clients
// This runs every hour to remove clients that haven't been seen in the last hour
func init() {
	go func() {
		for {
			time.Sleep(time.Hour)
			mu.Lock()
			for ip, cl := range clients {
				if time.Since(cl.lastSeen) > time.Hour {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()
}

// getLimiter returns an IP-specific limiter for the given r
func getLimiter(ip string, r *http.Request) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	route := r.URL.Path
	limit, ok := routeLimits[route]
	if !ok {
		// no limit configured for this route
		return nil
	}

	cli, exists := clients[ip]
	if !exists {
		cli = &client{
			limiter: rate.NewLimiter(rate.Every(time.Minute/time.Duration(limit)), int(limit)),
		}
		clients[ip] = cli
	}
	cli.lastSeen = time.Now()
	return cli.limiter
}

// RateLimit middleware
func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if limiter := getLimiter(ip, r); limiter != nil && !limiter.Allow() {

			logger.Warn(
				server.ServerError.TooManyRequests,
				errors.New("rate limit exceeded"),
				logrus.Fields{"ip": ip, "route": r.URL.Path},
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