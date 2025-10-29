package private

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	onboardingRepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
)

type Services struct {
	OTP        otp.S
	Phoenix    phoenixservice.Service
	Onboarding onboarding.Service
}

func New() *Services {
	redisClient := redis.Client
	redisRepo := redis.NewRedisRepo(redisClient)

	dbConn := db.GetDB()
	userrepo := user.NewUserRepo(dbConn)
	onboardingrepo := onboardingRepo.NewOBDetailsRepository(dbConn)

	phoenixClient := phoenixservice.NewBrevoClient()
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otp.New(userrepo, redisRepo, phoenixService)
	onboardingService := onboarding.NewService(userrepo, onboardingrepo)
	return &Services{
		OTP:        otpService,
		Phoenix:    phoenixService,
		Onboarding: onboardingService,
	}
}
