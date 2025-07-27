package private

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/otp"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/redis"
)

type PrivateServices struct {
	OTP otp.OTPService
}

func New() *PrivateServices {
	redisClient := redis.RedisClient
	redisRepo := redis.NewRedisRepo(redisClient)
	otpService := otp.New(redisRepo)
	return &PrivateServices{
		OTP: otpService,
	}
}