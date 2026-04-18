package public

import (
	"github.com/RGisanEclipse/AVYO-Server/internal/db"
	"github.com/RGisanEclipse/AVYO-Server/internal/db/onboarding"
	"github.com/RGisanEclipse/AVYO-Server/internal/db/redis"
	"github.com/RGisanEclipse/AVYO-Server/internal/db/user"
	otpservice "github.com/RGisanEclipse/AVYO-Server/internal/service/private/otp"
	phoenixservice "github.com/RGisanEclipse/AVYO-Server/internal/service/private/phoenix"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/public/auth"
)

type Services struct {
	Auth *auth.Service
}

func New() *Services {
	dbConn := db.GetDB()
	redisClient := redis.Client

	userrepo := user.NewUserRepo(dbConn)
	redisRepo := redis.NewRedisRepo(redisClient)
	onboardingRepo := onboarding.NewOBDetailsRepository(dbConn)

	phoenixClient := phoenixservice.NewBrevoClient()
	phoenixService := phoenixservice.New(userrepo, phoenixClient)

	otpService := otpservice.New(userrepo, redisRepo, phoenixService)
	authService := auth.NewService(userrepo, redisRepo, onboardingRepo, otpService)

	return &Services{
		Auth: authService,
	}
}
