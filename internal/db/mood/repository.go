package mood

import (
	"context"
	"time"

	mood "github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

type Repository interface {
	SaveMood(ctx context.Context, data mood.Entry) error
	GetMoodByDuration(ctx context.Context, userId string, from time.Time) ([]mood.Entry, error)
}
