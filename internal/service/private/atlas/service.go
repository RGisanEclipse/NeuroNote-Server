package atlas

import (
	"context"

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
	GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, error)
	GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, error)
	GetDashboardData(ctx context.Context, request model.MoodTrendRequest) (*model.DashboardResponse, error)
}
