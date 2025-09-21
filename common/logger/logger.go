package logger

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	apperror "github.com/RGisanEclipse/NeuroNote-Server/common/error"
	"github.com/sirupsen/logrus"
)

type Fields = logrus.Fields

var log = logrus.New()

func init() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		PrettyPrint:     false,
	})
	log.SetLevel(logrus.DebugLevel)
}

// captureStack collects a trimmed stack trace (skips logger frames)
func captureStack() string {
	const maxFrames = 50
	var pcs [maxFrames]uintptr
	n := runtime.Callers(2, pcs[:])
	if n == 0 {
		return "empty stack trace"
	}
	frames := runtime.CallersFrames(pcs[:n])
	var sb strings.Builder

	frameNum := 0
	for {
		frame, more := frames.Next()
		sb.WriteString(fmt.Sprintf("#%d %s:%d %s\n",
			frameNum,
			frame.File,
			frame.Line,
			frame.Function,
		))
		if !more {
			break
		}
		frameNum++
	}
	return strings.TrimSpace(sb.String())
}

// captureCaller returns just the calling function name and location
func captureCaller() string {
	const maxFrames = 10
	var pcs [maxFrames]uintptr
	n := runtime.Callers(3, pcs[:])
	if n == 0 {
		return "unknown caller"
	}
	frames := runtime.CallersFrames(pcs[:n])
	frame, _ := frames.Next()
	return fmt.Sprintf("%s:%d %s", frame.File, frame.Line, frame.Function)
}

// helpers

func Info(msg string, fields ...Fields) {
	if len(fields) > 0 {
		log.WithFields(fields[0]).Info(msg)
	} else {
		log.Info(msg)
	}
}

func Debug(msg string, fields ...Fields) {
	if len(fields) > 0 {
		log.WithFields(fields[0]).Debug(msg)
	} else {
		log.Debug(msg)
	}
}

func Error(msg string, err error, errorCode *apperror.Code, fields ...Fields) {
	var errStr string
	if err != nil {
		errStr = err.Error()
	}

	entry := log.WithFields(Fields{
		"error":      errStr,
		"error_code": errorCode.Code,
		"status":     errorCode.Status,
		"caller":     captureCaller(),
		"stack":      captureStack(),
	})
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Error(msg)
}

func Warn(msg string, err error, errorCode *apperror.Code, fields ...Fields) {
	if err == nil {
		err = errors.New(msg)
	}

	entry := log.WithFields(Fields{
		"error":      err.Error(),
		"error_code": errorCode.Code,
		"status":     errorCode.Status,
		"caller":     captureCaller(),
	})
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Warn(msg)
}
