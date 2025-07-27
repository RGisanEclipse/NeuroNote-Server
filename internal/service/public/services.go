package public

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
)

type PublicServices struct {
	Auth auth.AuthService 
}

func New() *PublicServices {
	dbConn := db.GetDB()
	redisClient := redis.RedisClient

	userRepo := user.NewGormRepo(dbConn)
	redisRepo := redis.NewRedisRepo(redisClient)

	authService := auth.New(userRepo, redisRepo)

	return &PublicServices{
		Auth: authService,
	}
}