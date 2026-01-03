package private

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
	moodRepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/mood"
	onboardingRepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/mood"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/onboarding"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	phoenixservice "github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/phoenix"
)

type Services struct {
	OTP        otp.S
	Phoenix    phoenixservice.Service
	Onboarding onboarding.Service
	Mood       mood.Service
}

func New() *Services {
	redisClient := redis.Client
	redisRepo := redis.NewRedisRepo(redisClient)

	dbConn := db.GetDB()
	userrepo := user.NewUserRepo(dbConn)
	onboardingrepo := onboardingRepo.NewOBDetailsRepository(dbConn)
	moodrepo := moodRepo.NewMoodRepository(dbConn)

	phoenixClient := phoenixservice.NewBrevoClient()
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otp.New(userrepo, redisRepo, phoenixService)
	onboardingService := onboarding.NewService(userrepo, onboardingrepo)
	moodService := mood.NewService(moodrepo)
	return &Services{
		OTP:        otpService,
		Phoenix:    phoenixService,
		Onboarding: onboardingService,
		Mood:       moodService,
	}
}
