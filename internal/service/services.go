package service

import (
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/auth"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db/user"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/db"
)

type Services struct {
	Auth auth.AuthService 
}

func New() *Services {
	userRepo := user.NewGormRepo(db.GetDB())
	return &Services{
		Auth: auth.New(userRepo),
	}
}