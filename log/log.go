package log

import (
	"log"
	"net/http"
	"os"
)

const (
	quiteLevel byte = iota
	errorLevel
	infoLevel
	debugLevel
)

var logLevel byte = infoLevel

var infoLogger = log.New(os.Stdout, "[INFO ] ", log.Ldate|log.Ltime)
var errorLogger = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime)
var debugLogger = log.New(os.Stdout, "[DEBUG] ", log.Ldate|log.Ltime)

var accessLogger = log.New(os.Stdout, "", log.Ldate|log.Ltime)

func Info(format string, v ...any) {
	if logLevel >= infoLevel {
		infoLogger.Printf(format, v...)
	}
}

func Error(format string, v ...any) {
	if logLevel >= errorLevel {
		errorLogger.Printf(format, v...)
	}
}

func Debug(format string, v ...any) {
	if logLevel >= debugLevel {
		debugLogger.Printf(format, v...)
	}
}

func AccessLogRequest(r *http.Request) {
	accessLogger.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
	if logLevel >= debugLevel {
		for k, v := range r.Header {
			accessLogger.Printf("%v: %v\n", k, v)
		}
	}
}

func AccessLogResult(r *http.Request, status int, message string) {
	accessLogger.Printf("%s %s %s - %d %s", r.RemoteAddr, r.Method, r.URL, status, message)
}

func SetLogLevel(level byte) {
	logLevel = level
}
