package logger

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var Log *logrus.Logger

// getLog 返回已初始化的 Logger，未初始化时使用 logrus 标准 logger
func getLog() *logrus.Logger {
	if Log != nil {
		return Log
	}
	return logrus.StandardLogger()
}

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
func Debug(args ...interface{}) { getLog().Debug(args...) }
func Info(args ...interface{})  { getLog().Info(args...) }
func Warn(args ...interface{})  { getLog().Warn(args...) }
func Error(args ...interface{}) { getLog().Error(args...) }
func Fatal(args ...interface{}) { getLog().Fatal(args...) }

// ---------- 格式化版本 ----------

func Debugf(format string, args ...interface{}) { getLog().Debugf(format, args...) }
func Infof(format string, args ...interface{})  { getLog().Infof(format, args...) }
func Warnf(format string, args ...interface{})  { getLog().Warnf(format, args...) }
func Errorf(format string, args ...interface{}) { getLog().Errorf(format, args...) }
func Fatalf(format string, args ...interface{}) { getLog().Fatalf(format, args...) }

// ---------- 带字段的结构化日志（可选）----------

func WithField(key string, value interface{}) *logrus.Entry {
	return getLog().WithField(key, value)
}

func WithFields(fields map[string]interface{}) *logrus.Entry {
	return getLog().WithFields(fields)
}
