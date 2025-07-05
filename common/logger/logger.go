package logger

import (
	"os"
	"runtime/debug"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		ForceColors:     true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	log.SetLevel(logrus.DebugLevel)
}

// Info logs an informational message with optional structured fields
func Info(msg string, fields ...logrus.Fields) {
	if len(fields) > 0 {
		log.WithFields(fields[0]).Info(msg)
	} else {
		log.Info(msg)
	}
}

// Warn logs a warning message
// WarnErr logs a warning message and an error
func Warn(msg string, err error, fields ...logrus.Fields) {
	entry := log.WithField("error", err.Error())
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Warn(msg)
}

// Debug logs a debug message
func Debug(msg string, fields ...logrus.Fields) {
	if len(fields) > 0 {
		log.WithFields(fields[0]).Debug(msg)
	} else {
		log.Debug(msg)
	}
}

// Error logs an error message and stack trace
func Error(msg string, err error, fields ...logrus.Fields) {
	entry := log.WithFields(logrus.Fields{
		"error": err.Error(),
		"stack": string(debug.Stack()),
	})
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Error(msg)
}