package private

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
)

type PrivateServices struct {
	OTP otp.OTPService
	Phoenix phoenixservice.PhoenixService
}

func New() *PrivateServices {
	redisClient := redis.RedisClient
	redisRepo := redis.NewRedisRepo(redisClient)

	dbConn := db.GetDB()
	userrepo := user.NewGormRepo(dbConn)

	phoenixClient := phoenixservice.NewBrevoClient() 
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otp.New(userrepo, redisRepo, phoenixService)
	return &PrivateServices{
		OTP: otpService,
		Phoenix: phoenixService,
	}
}