package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/server"
	dbErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/handler"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/rate"	
	"github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service"
	
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
	logger.Error(server.ServerError.MissingEnvVars, err)
	os.Exit(1)
	}

	// Database Initialization
	if err := db.Init(); err != nil {
		logger.Error(dbErr.DBError.ConnectionFailed, err)
		os.Exit(1)
	}

	// Redis Initialization
	redis.InitRedis()
	if err := redis.RedisClient.Ping(context.Background()).Err(); err != nil {
		logger.Error(dbErr.RedisError.ConnectionFailed, err)
		os.Exit(1)
	}
	// Construct Services
	services := service.New()
	
	// Setup Router with request logging middleware
	router := mux.NewRouter()
	router.Use(request.Middleware)

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Methods("GET")

	public := router.NewRoute().Subrouter()
	// Apply Rate Limiting Middleware to public routes
	public.Use(rate.RateLimit)
	handler.RegisterRoutes(public, services)

	// Setup Port and Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("NeuroNote-Server listening on :" + port)

	// Shut-Down Handling
	// This will gracefully shutdown the server on interrupt signal

	idleConnsClosed := make(chan struct{})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error(server.ServerError.ShutdownFailed, err)
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error(server.ServerError.HTTPServerError, err)
	}

	<-idleConnsClosed
	logger.Info("Server stopped gracefully")
}