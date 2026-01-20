package atlas

import (
	"context"
	"sort"
	"time"

	appError "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/RGisanEclipse/NeuroNote-Server/common/logger"
	requestMiddleWare "github.com/RGisanEclipse/NeuroNote-Server/internal/middleware/request"
	model "github.com/RGisanEclipse/NeuroNote-Server/internal/models/atlas"
	"github.com/RGisanEclipse/NeuroNote-Server/internal/models/mood"
)

func (s *service) getEntriesForRange(ctx context.Context, request model.MoodTrendRequest) ([]mood.Entry, *time.Location, time.Time, time.Time, int, *appError.Code) {
	requestId := requestMiddleWare.FromContext(ctx)
	logFields := logger.Fields{
		"userId":    request.UserId,
		"requestId": requestId,
		"start":     request.StartTime,
		"end":       request.EndTime,
	}

	if request.EndTime.Before(request.StartTime) {
		logger.Warn(appError.MDInvalidDaysRange.Message, nil, appError.MDInvalidDaysRange, logFields)
		return nil, nil, time.Time{}, time.Time{}, 0, appError.MDInvalidDaysRange
	}

	tz := &request.TimeZone
	if request.TimeZone.String() == "" {
		tz = time.UTC
	}

	startInTz := request.StartTime.In(tz)
	endInTz := request.EndTime.In(tz)
	startOfDay := time.Date(startInTz.Year(), startInTz.Month(), startInTz.Day(), 0, 0, 0, 0, tz)
	endOfDay := time.Date(endInTz.Year(), endInTz.Month(), endInTz.Day(), 0, 0, 0, 0, tz)
	days := int(endOfDay.Sub(startOfDay).Hours()/24) + 1
	fromUnix := startInTz.Unix()

	entries, err := s.moodReader.GetMoodByDuration(ctx, request.UserId, fromUnix)
	if err != nil {
		logFields["error"] = err.Error()
		logger.Error(appError.DBQueryFailed.Message, err, appError.DBQueryFailed, logFields)
		return nil, nil, time.Time{}, time.Time{}, 0, appError.ServerInternalError
	}

	filtered := make([]mood.Entry, 0, len(entries))
	for _, entry := range entries {
		createdAt := time.Unix(entry.CreatedAt, 0).In(tz)
		if createdAt.Before(startInTz) || createdAt.After(endInTz) {
			continue
		}
		filtered = append(filtered, entry)
	}

	return filtered, tz, startOfDay, endOfDay, days, nil
}

func (s *service) getMoodTrend(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, error) {
	entries, tz, startOfDay, _, days, rangeErr := s.getEntriesForRange(ctx, request)
	if rangeErr != nil {
		return nil, rangeErr
	}

	counts := map[string]map[mood.Type]int{}
	latest := map[string]map[mood.Type]int64{}

	for _, entry := range entries {
		createdAt := time.Unix(entry.CreatedAt, 0).In(tz)
		dayKey := createdAt.Format("2006-01-02")
		if counts[dayKey] == nil {
			counts[dayKey] = map[mood.Type]int{}
			latest[dayKey] = map[mood.Type]int64{}
		}

		counts[dayKey][entry.Mood]++
		createdAtUnix := createdAt.Unix()
		if createdAtUnix > latest[dayKey][entry.Mood] {
			latest[dayKey][entry.Mood] = createdAtUnix
		}
	}

	result := map[string]*mood.Type{}

	// Select Dominant mood per day
	for i := 0; i < days; i++ {
		day := startOfDay.AddDate(0, 0, i).Format("2006-01-02")
		var bestMood *mood.Type
		bestCount := 0
		bestLatest := int64(0)

		for m, c := range counts[day] {
			l := latest[day][m]
			if c > bestCount || (c == bestCount && l > bestLatest) {
				mm := m
				bestMood = &mm
				bestCount = c
				bestLatest = l
			}
		}

		result[day] = bestMood
	}

	logger.Info("Mood trend fetched successfully", logger.Fields{
		"userId":    request.UserId,
		"requestId": requestMiddleWare.FromContext(ctx),
		"start":     request.StartTime,
		"end":       request.EndTime,
	})
	return &model.MoodTrendResponse{Data: result}, nil
}

func (s *service) GetWeeklyMoodStripData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTrendResponse, error) {
	tz := &request.TimeZone
	if request.TimeZone.String() == "" {
		tz = time.UTC
	}

	now := time.Now().In(tz)
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, tz)
	startOfWeek := startOfToday.AddDate(0, 0, -int(startOfToday.Weekday()))
	endOfWeek := startOfWeek.AddDate(0, 0, 7).Add(-time.Nanosecond)
	request.StartTime = startOfWeek
	request.EndTime = endOfWeek

	return s.getMoodTrend(ctx, request)
}

func (s *service) GetMonthlyTopMoodsData(ctx context.Context, request model.MoodTrendRequest) (*model.MoodTop3Response, error) {
	tz := &request.TimeZone
	if request.TimeZone.String() == "" {
		tz = time.UTC
	}

	now := time.Now().In(tz)
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, tz)
	request.StartTime = startOfToday.AddDate(0, 0, -29)
	request.EndTime = now

	entries, tz, _, _, _, rangeErr := s.getEntriesForRange(ctx, request)
	if rangeErr != nil {
		return nil, rangeErr
	}

	if len(entries) == 0 {
		return &model.MoodTop3Response{Data: []model.MoodPercentage{}}, nil
	}

	type moodStat struct {
		mood   mood.Type
		count  int
		latest int64
	}

	counts := map[mood.Type]*moodStat{}
	total := 0

	for _, entry := range entries {
		createdAt := time.Unix(entry.CreatedAt, 0).In(tz)
		stat := counts[entry.Mood]
		if stat == nil {
			stat = &moodStat{mood: entry.Mood}
			counts[entry.Mood] = stat
		}

		stat.count++
		total++
		createdAtUnix := createdAt.Unix()
		if createdAtUnix > stat.latest {
			stat.latest = createdAtUnix
		}
	}

	stats := make([]moodStat, 0, len(counts))
	for _, stat := range counts {
		stats = append(stats, *stat)
	}

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count == stats[j].count {
			return stats[i].latest > stats[j].latest
		}
		return stats[i].count > stats[j].count
	})

	limit := 3
	if len(stats) < limit {
		limit = len(stats)
	}

	result := make([]model.MoodPercentage, 0, limit)
	for i := 0; i < limit; i++ {
		stat := stats[i]
		percentage := (float64(stat.count) / float64(total)) * 100
		result = append(result, model.MoodPercentage{
			Mood:       stat.mood,
			Percentage: percentage,
		})
	}

	return &model.MoodTop3Response{Data: result}, nil
}
