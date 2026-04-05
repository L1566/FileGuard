package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

func Init(level string, format string) {
	Log = logrus.New()
	Log.SetOutput(os.Stdout)

	// 设置日志级别
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.InfoLevel
	}
	Log.SetLevel(lvl)

	// 设置输出格式
	if format == "json" {
		Log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}
}

// 快捷函数
func Debug(args ...interface{}) { Log.Debug(args...) }
func Info(args ...interface{})  { Log.Info(args...) }
func Warn(args ...interface{})  { Log.Warn(args...) }
func Error(args ...interface{}) { Log.Error(args...) }
func Fatal(args ...interface{}) { Log.Fatal(args...) }

// ---------- 格式化版本 ----------

func Debugf(format string, args ...interface{}) {
	Log.Debugf(format, args...)
}

func Infof(format string, args ...interface{}) {
	Log.Infof(format, args...)
}

func Warnf(format string, args ...interface{}) {
	Log.Warnf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	Log.Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	Log.Fatalf(format, args...)
}

// ---------- 带字段的结构化日志（可选）----------

func WithField(key string, value interface{}) *logrus.Entry {
	return Log.WithField(key, value)
}

func WithFields(fields map[string]interface{}) *logrus.Entry {
	return Log.WithFields(fields)
}
