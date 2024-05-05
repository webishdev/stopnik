package log

import (
	"log"
	"os"
)

var infoLogger = log.New(os.Stdout, "", 0)
var errorLogger = log.New(os.Stderr, "", 0)
var debugLogger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

func Info(format string, v ...any) {
	infoLogger.Printf(format, v...)
}

func Error(format string, v ...any) {
	errorLogger.Printf(format, v...)
}

func Debug(format string, v ...any) {
	debugLogger.Printf(format, v...)
}
