package log

import (
	"log/slog"
	"net/http"
	"os"
)

var currentLogLevel slog.Level

var textHandler = *slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	//Level: slog.LevelError,
})

var accessLogHandler = *slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	//Level: slog.LevelError,
})

var infoLogger = slog.NewLogLogger(&textHandler, slog.LevelInfo)
var warnLogger = slog.NewLogLogger(&textHandler, slog.LevelWarn)
var errorLogger = slog.NewLogLogger(&textHandler, slog.LevelError)
var debugLogger = slog.NewLogLogger(&textHandler, slog.LevelDebug)

var accessLogger = slog.NewLogLogger(&accessLogHandler, slog.LevelInfo)

func SetLogLevel(level string) {
	currentLogLevel = getLogLevelFromString(level)
	textHandler = *slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: currentLogLevel,
	})
}

func Info(format string, v ...any) {
	infoLogger.Printf(format, v...)
}

func Warn(format string, v ...any) {
	warnLogger.Printf(format, v...)
}

func Error(format string, v ...any) {
	errorLogger.Printf(format, v...)
}

func Debug(format string, v ...any) {
	debugLogger.Printf(format, v...)
}

func IsDebug() bool {
	return currentLogLevel == slog.LevelDebug
}

func AccessLogRequest(r *http.Request) {
	accessLogger.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
}

func AccessLogResult(r *http.Request, status int, message string) {
	accessLogger.Printf("%s %s %s - %d %s", r.RemoteAddr, r.Method, r.URL, status, message)
}

func getLogLevelFromString(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
