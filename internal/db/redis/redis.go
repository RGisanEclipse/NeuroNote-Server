package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"
	"errors"

	"github.com/redis/go-redis/v9"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/error/db"
	typeErr "github.com/RGisanEclipse/NeuroNote-Server/internal/error/types"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/utils/types"
)

var RedisClient *redis.Client

type RedisRepo struct {
	client *redis.Client
}

func NewRedisRepo(client *redis.Client) *RedisRepo {
	return &RedisRepo{client: client}
}

func InitRedis() error { 
	redisHost := os.Getenv("REDIS_HOST") 
	redisPort := os.Getenv("REDIS_PORT") 

	if redisHost == "" || redisPort == "" {
		err := fmt.Errorf("missing REDIS_HOST or REDIS_PORT environment variables for Redis")
		logger.Error(db.RedisError.ConnectionFailed, err)
		return err 
	}

	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	tlsEnabled := os.Getenv("REDIS_TLS") == "true"

	options := &redis.Options{
		Addr:     redisAddr,     
		DB:       0,             
	}

	if tlsEnabled {
		options.TLSConfig = &tls.Config{} 
	}

	maxRetries := 10
	var err error
	for i := 0; i < maxRetries; i++ {
		RedisClient = redis.NewClient(options)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) 
		err = RedisClient.Ping(ctx).Err() 
		cancel() 

		if err == nil {
			logger.Info("Connected to Redis")
			return nil 
		}

		RedisClient.Close() 
		time.Sleep(2 * time.Second) 
	}

	return errors.New(db.RedisError.ConnectionFailed)
}

func (r *RedisRepo) SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	userId, err := types.ConvertStringToUint(userID)
	if err != nil {
		logger.Error(typeErr.TypeError.TypeCastingError, err, logger.Fields{"userID": userID})
		return nil
	}
	key := getRefreshTokenKey(userId)
	return r.client.Set(ctx, key, token, expiry).Err()
}

func (r *RedisRepo) GetRefreshToken(ctx context.Context, userID string) (string, error) {
	userId, err := types.ConvertStringToUint(userID)
	if err != nil {
		logger.Error(typeErr.TypeError.TypeCastingError, err, logger.Fields{"userID": userID})
		return "", err
	}
	key := getRefreshTokenKey(userId)
	return r.client.Get(ctx, key).Result()
}

func (r *RedisRepo) DeleteRefreshToken(ctx context.Context, userID string) error {
	userId, err := types.ConvertStringToUint(userID)
	if err != nil {
		logger.Error(typeErr.TypeError.TypeCastingError, err, logger.Fields{"userID": userID})
		return err
	}
	key := getRefreshTokenKey(userId)
	return r.client.Del(ctx, key).Err()
}

func getRefreshTokenKey(userID uint) string {
	return fmt.Sprintf("refresh_token:%d", userID)
}

// OTPService Methods
func (r *RedisRepo) SetOTP(ctx context.Context, key string, otp string, ttl time.Duration) error {
	return r.client.Set(ctx, key, otp, ttl).Err()
}

func (r *RedisRepo) GetOTP(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

func (r *RedisRepo) DeleteOTP(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func getOTPKey(identifier string) string {
	return fmt.Sprintf("otp:%s", identifier)
}