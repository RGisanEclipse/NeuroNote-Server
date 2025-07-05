package logger

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func init() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		PrettyPrint:     false,
	})
	log.SetLevel(logrus.DebugLevel)
}

//────────────────────────────────────────────────────────────
// captureStack returns a slice of frames starting *after*
// this logger’s own functions (skip=3 is “just right”).
//────────────────────────────────────────────────────────────
func captureStack() []string {
	const maxFrames = 32
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(3, pcs) // skip 3 => callers above logger.Error
	frames := runtime.CallersFrames(pcs[:n])

	var out []string
	for {
		f, more := frames.Next()
		if !strings.Contains(f.Function, "/common/logger") { // ignore logger frames
			out = append(out, fmt.Sprintf("%s\n\t%s:%d", f.Function, f.File, f.Line))
		}
		if !more {
			break
		}
	}
	return out
}

//────────────────────────────────────────────────────────────
// Public helpers
//────────────────────────────────────────────────────────────
func Info(msg string, fields ...logrus.Fields) {
	if len(fields) > 0 {
		log.WithFields(fields[0]).Info(msg)
	} else {
		log.Info(msg)
	}
}

func Debug(msg string, fields ...logrus.Fields) {
	if len(fields) > 0 {
		log.WithFields(fields[0]).Debug(msg)
	} else {
		log.Debug(msg)
	}
}

func Warn(msg string, err error, fields ...logrus.Fields) {
	if err == nil {
		err = errors.New(msg) // ensure non-nil
	}
	entry := log.WithFields(logrus.Fields{
		"error":    err.Error(),
		"function": captureStack()[0], // first non-logger frame
	})
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Warn(msg)
}

func Error(msg string, err error, fields ...logrus.Fields) {
	stack := captureStack() // full slice

	entry := log.WithFields(logrus.Fields{
		"error":    err.Error(),
		"function": stack[0], // top frame for quick glance
		"stack":    stack,    // entire stack as JSON array
	})

	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Error(msg)
}