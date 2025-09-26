package private

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
)

type Services struct {
	OTP     otp.S
	Phoenix phoenixservice.Service
}

func New() *Services {
	redisClient := redis.Client
	redisRepo := redis.NewRedisRepo(redisClient)

	dbConn := db.GetDB()
	userrepo := user.NewGormRepo(dbConn)

	phoenixClient := phoenixservice.NewBrevoClient()
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otp.New(userrepo, redisRepo, phoenixService)
	return &Services{
		OTP:     otpService,
		Phoenix: phoenixService,
	}
}
