package db

import (
	"fmt"
	"os"
	"sync"

	"github.com/RGisanEclipse/AVYO-Server/internal/models/activity"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/mood"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/onboarding"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/RGisanEclipse/AVYO-Server/common/logger"
	"github.com/RGisanEclipse/AVYO-Server/internal/db/common"
	"github.com/RGisanEclipse/AVYO-Server/internal/models/user"
)

// Init connects to Postgres and runs migrations.
var once sync.Once

func Init() error {
	var err error

	once.Do(func() {
		dsn := fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Kolkata",
			os.Getenv("DB_HOST"),
			os.Getenv("DB_USER"),
			os.Getenv("DB_PASSWORD"),
			os.Getenv("DB_NAME"),
			os.Getenv("DB_PORT"),
		)

		common.DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return
		}

		if err = common.DB.AutoMigrate(
			&user.Model{},
			&onboarding.Model{},
			&mood.Entry{},
			&activity.DailyEntry{},
			&activity.Streak{},
		); err != nil {
			return
		}

		logger.Info("Connected to Postgres and ran dev migrations")
	})

	return err
}

func GetDB() *gorm.DB {
	return common.DB
}
