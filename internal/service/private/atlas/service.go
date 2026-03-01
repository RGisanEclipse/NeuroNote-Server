package atlas

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/nova"
)

type service struct {
	nova nova.Service
}

func NewService(novaService nova.Service) Service {
	return &service{
		nova: novaService,
	}
}

type Service interface {
	GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code)
	GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, *appError.Code)
	GetDashboardData(ctx context.Context, request model.MoodTrendRequest) (*model.DashboardResponse, *appError.Code)
}
