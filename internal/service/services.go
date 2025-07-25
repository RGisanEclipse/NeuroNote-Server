package service

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
)

type Services struct {
	Auth auth.AuthService 
}

func New() *Services {
	dbConn := db.GetDB()
	redisClient := redis.RedisClient

	userRepo := user.NewGormRepo(dbConn)
	redisRepo := redis.NewRedisRepo(redisClient)

	authService := auth.New(userRepo, redisRepo)

	return &Services{
		Auth: authService,
	}
}