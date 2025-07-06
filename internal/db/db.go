package db

import (
	"fmt"
	"os"
	"sync"
	
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/common"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/user"
	
)

// Init connects to Postgres and runs migrations.
var once sync.Once

func Init() error {
	var err error
	once.Do(func() {
		dataBaseSource := fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Kolkata",
			os.Getenv("DB_HOST"),
			os.Getenv("DB_USER"),
			os.Getenv("DB_PASSWORD"),
			os.Getenv("DB_NAME"),
			os.Getenv("DB_PORT"),
		)

		common.DB, err = gorm.Open(postgres.Open(dataBaseSource), &gorm.Config{})
		if err != nil {
			return
		}

		// Auto-migrate the User table.
		if err = common.DB.AutoMigrate(&user.UserModel{}); err != nil {
			return
		}
		logger.Info("Connected to Postgres and ran migrations")
	})

	return err
}
func GetDB() *gorm.DB {
	return common.DB
}