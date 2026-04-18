package atlas

import (
	"context"
	"encoding/json"

	appError "github.com/RGisanEclipse/AVYO-Server/common/error"
	activityRepo "github.com/RGisanEclipse/AVYO-Server/internal/db/activity"
	model "github.com/RGisanEclipse/AVYO-Server/internal/models/atlas"
	syncModel "github.com/RGisanEclipse/AVYO-Server/internal/models/sync"
	moodService "github.com/RGisanEclipse/AVYO-Server/internal/service/private/mood"
	"github.com/RGisanEclipse/AVYO-Server/internal/service/private/nova"
)

const MaxSyncOperations = 500

// OperationHandler processes a single named operation type for a given user.
type OperationHandler interface {
	Process(ctx context.Context, userID string, payload json.RawMessage) *appError.Code
}

type service struct {
	nova         nova.Service
	activityRepo activityRepo.Repository
	handlers     map[string]OperationHandler
}

func NewService(novaService nova.Service, activityRepository activityRepo.Repository, moodSvc moodService.Service) Service {
	s := &service{
		nova:         novaService,
		activityRepo: activityRepository,
	}
	s.handlers = map[string]OperationHandler{
		"mood": &moodHandler{moodSvc: moodSvc},
	}
	return s
}

type Service interface {
	GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, *appError.Code)
	GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, *appError.Code)
	GetDashboardData(ctx context.Context, request model.MoodTrendRequest) (*model.DashboardResponse, *appError.Code)
	BulkSync(ctx context.Context, userID string, req syncModel.SyncRequest) *syncModel.SyncResponse
}
