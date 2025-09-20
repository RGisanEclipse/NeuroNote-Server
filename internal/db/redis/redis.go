package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/redis/go-redis/v9"
)

var Client *redis.Client

type Repo struct {
	client *redis.Client
}

func NewRedisRepo(client *redis.Client) *Repo {
	return &Repo{client: client}
}

func InitRedis() error {
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")

	if redisHost == "" || redisPort == "" {
		err := fmt.Errorf("missing REDIS_HOST or REDIS_PORT environment variables for Redis")
		logger.Error(appError.RedisConnectionFailed.Message, err,appError.RedisConnectionFailed)
		return err
	}

	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	tlsEnabled := os.Getenv("REDIS_TLS") == "true"

	options := &redis.Options{
		Addr: redisAddr,
		DB:   0,
	}

	if tlsEnabled {
		options.TLSConfig = &tls.Config{}
	}

	maxRetries := 10
	var err error
	for i := 0; i < maxRetries; i++ {
		Client = redis.NewClient(options)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = Client.Ping(ctx).Err()
		cancel()

		if err == nil {
			logger.Info("Connected to Redis")
			return nil
		}

		err := Client.Close()
		if err != nil {
			return err
		}
		time.Sleep(2 * time.Second)
	}

	return appError.RedisConnectionFailed
}

func (r *Repo) SetRefreshToken(ctx context.Context, userID string, token string, expiry time.Duration) error {
	key := getRefreshTokenKey(userID)
	return r.client.Set(ctx, key, token, expiry).Err()
}

func (r *Repo) GetRefreshToken(ctx context.Context, userID string) (string, error) {
	key := getRefreshTokenKey(userID)
	return r.client.Get(ctx, key).Result()
}

func (r *Repo) DeleteRefreshToken(ctx context.Context, userID string) error {
	key := getRefreshTokenKey(userID)
	return r.client.Del(ctx, key).Err()
}

func getRefreshTokenKey(userID string) string {
	return fmt.Sprintf("refresh_token:%s", userID)
}

// SetOTP OTPService Methods
func (r *Repo) SetOTP(ctx context.Context, userId string, otp string, ttl time.Duration, purpose string) error {
	key := getOTPKey(userId, purpose)
	return r.client.Set(ctx, key, otp, ttl).Err()
}

func (r *Repo) GetOTP(ctx context.Context, userId string, purpose string) (string, error) {
	key := getOTPKey(userId, purpose)
	return r.client.Get(ctx, key).Result()
}

func (r *Repo) DeleteOTP(ctx context.Context, userId string, purpose string) error {
	key := getOTPKey(userId, purpose)
	return r.client.Del(ctx, key).Err()
}

func getOTPKey(userID string, purpose string) string {
	return fmt.Sprintf("otp:%s:%s", userID, purpose)
}

func (r *Repo) SetPasswordResetFlag(ctx context.Context, userId string, ttl time.Duration) error {
	key := getPasswordResetKey(userId)
	return r.client.Set(ctx, key, "true", ttl).Err()
}

func (r *Repo) CheckPasswordResetFlag(ctx context.Context, userId string) (bool, error) {
	key := getPasswordResetKey(userId)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (r *Repo) DeletePasswordResetFlag(ctx context.Context, userId string) error {
	key := getPasswordResetKey(userId)
	return r.client.Del(ctx, key).Err()
}

func (r *Repo) GetPasswordResetKey(userId string) string {
	return fmt.Sprintf("password_reset_verified:%s", userId)
}

func getPasswordResetKey(userId string) string {
	return fmt.Sprintf("password_reset_verified:%s", userId)
}
