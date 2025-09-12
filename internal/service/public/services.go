package public

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
	otpservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"

)

type PublicServices struct {
	Auth auth.AuthService 
}

func New() *PublicServices {
	dbConn := db.GetDB()
	redisClient := redis.RedisClient

	userrepo := user.NewGormRepo(dbConn)
	redisRepo := redis.NewRedisRepo(redisClient)

	phoenixClient := phoenixservice.NewBrevoClient() 
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otpservice.New(userrepo, redisRepo, phoenixService)
	authService := auth.New(userrepo, redisRepo, otpService)

	return &PublicServices{
		Auth: authService,
	}
}