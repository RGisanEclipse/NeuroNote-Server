package logger

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

// public alias so callers can write logger.Fields{…} 
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
func captureStack() []string {
	const maxFrames = 32
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(3, pcs) 
	frames := runtime.CallersFrames(pcs[:n])

	var out []string
	for {
		f, more := frames.Next()
		if !strings.Contains(f.Function, "/common/logger") { 
			out = append(out, fmt.Sprintf("%s\n\t%s:%d", f.Function, f.File, f.Line))
		}
		if !more {
			break
		}
	}
	return out
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

func Warn(msg string, err error, fields ...Fields) {
	if err == nil {
		err = errors.New(msg) 
	}

	entry := log.WithFields(Fields{
		"error":    err.Error(),
		"function": captureStack()[0],
	})
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Warn(msg)
}

func Error(msg string, err error, fields ...Fields) {
	var errStr string
	if err != nil {
		errStr = err.Error()
	}

	stack := captureStack()
	entry := log.WithFields(Fields{
		"error":    errStr,
		"function": stack[0], 
		"stack":    stack,    
	})
	if len(fields) > 0 {
		entry = entry.WithFields(fields[0])
	}
	entry.Error(msg)
}