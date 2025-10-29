package public

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	otpservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/public/auth"
)

type Services struct {
	Auth *auth.Service
}

func New() *Services {
	dbConn := db.GetDB()
	redisClient := redis.Client

	userrepo := user.NewUserRepo(dbConn)
	redisRepo := redis.NewRedisRepo(redisClient)

	phoenixClient := phoenixservice.NewBrevoClient()
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otpservice.New(userrepo, redisRepo, phoenixService)
	authService := auth.NewService(userrepo, redisRepo, otpService)

	return &Services{
		Auth: authService,
	}
}
