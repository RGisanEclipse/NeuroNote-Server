package atlas

import (
	"context"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	activityRepo "github.com/RGisanEclipse/NeuroNote-Server/internal/db/activity"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/service/private/nova"
)

type service struct {
	nova         nova.Service
	activityRepo activityRepo.Repository
}

func NewService(novaService nova.Service, activityRepository activityRepo.Repository) Service {
	return &service{
		nova:         novaService,
		activityRepo: activityRepository,
	}
}

type Service interface {
	GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code)
	GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, *appError.Code)
	GetDashboardData(ctx context.Context, request model.MoodTrendRequest) (*model.DashboardResponse, *appError.Code)
}
