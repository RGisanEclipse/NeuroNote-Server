package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type LokiHook struct {
	URL       string
	Labels    map[string]string
	BatchWait time.Duration
	BatchSize int
}

func (hook *LokiHook) Fire(entry *logrus.Entry) error {
	logEntry := make(map[string]interface{})
	for k, v := range entry.Data {
		logEntry[k] = v
	}
	logEntry["message"] = entry.Message
	logEntry["level"] = entry.Level.String()
	logEntry["time"] = entry.Time.Format(time.RFC3339)

	jsonValue, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}

	logData := map[string]interface{}{
		"streams": []map[string]interface{}{
			{
				"stream": hook.Labels,
				"values": [][]string{
					{
						fmt.Sprintf("%d", time.Now().UnixNano()),
						string(jsonValue),
					},
				},
			},
		},
	}

	payload, err := json.Marshal(logData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", hook.URL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	_, err = client.Do(req)
	return err
}

func (hook *LokiHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
