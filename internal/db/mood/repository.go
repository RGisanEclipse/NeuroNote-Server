package mood

import (
	"context"

	mood "github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

type Repository interface {
	SaveMood(ctx context.Context, data mood.Entry) error
	GetMoodByDuration(ctx context.Context, userId string, from int64) ([]mood.Entry, error)
}
