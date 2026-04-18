package private

import (
	"github.com/RGisanEclipse/AVYO-Server/internal/db"
	activityRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/activity"
	moodRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/mood"
	onboardingRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/onboarding"
	"github.com/RGisanEclipse/AVYO-Server/internal/db/redis"
	"github.com/RGisanEclipse/AVYO-Server/internal/db/user"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/private/atlas"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/private/mood"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/private/nova"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/private/onboarding"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/private/otp"
	phoenixservice "github.com/RGisanEclipse/AVYO-Server/internal/service/private/phoenix"
)

type Services struct {
	OTP        otp.S
	Phoenix    phoenixservice.Service
	Onboarding onboarding.Service
	Mood       mood.Service
	Atlas      atlas.Service
}

func New() *Services {
	redisClient := redis.Client
	redisRepo := redis.NewRedisRepo(redisClient)

	dbConn := db.GetDB()
	userrepo := user.NewUserRepo(dbConn)
	onboardingrepo := onboardingRepo.NewOBDetailsRepository(dbConn)
	moodrepo := moodRepo.NewMoodRepository(dbConn)
	activityrepo := activityRepo.NewActivityRepository(dbConn)

	phoenixClient := phoenixservice.NewBrevoClient()
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otp.New(userrepo, redisRepo, phoenixService)
	onboardingService := onboarding.NewService(userrepo, onboardingrepo)
	moodService := mood.NewService(moodrepo)
	novaService := nova.NewService(moodrepo, activityrepo)
	atlasService := atlas.NewService(novaService, activityrepo, moodService)

	return &Services{
		OTP:        otpService,
		Phoenix:    phoenixService,
		Onboarding: onboardingService,
		Mood:       moodService,
		Atlas:      atlasService,
	}
}
