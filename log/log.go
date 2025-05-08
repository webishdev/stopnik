package log

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
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
	addr := getAddrFromRequest(r)
	accessLogger.Printf("%s - %s - %s %s", addr, r.Host, r.Method, r.URL)
}

func AccessLogResult(r *http.Request, status int, message string) {
	addr := getAddrFromRequest(r)
	accessLogger.Printf("%s - %s - %s %s - %d %s", addr, r.Host, r.Method, r.URL, status, message)
}

func AccessLogInvalidLogin(r *http.Request, format string, v ...any) {
	addr := getAddrFromRequest(r)
	logEntry := fmt.Sprintf(format, v...)
	accessLogger.Printf("%s - %s", addr, logEntry)
}

func getAddrFromRequest(r *http.Request) string {
	var result []string
	result = append(result, r.RemoteAddr)
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		result = append(result, "X-Forwarded-For: "+forwardedFor)
	}

	realIp := r.Header.Get("X-Real-Ip")
	if realIp != "" {
		result = append(result, "X-Real-Ip: "+realIp)
	}

	return strings.Join(result, ", ")
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
