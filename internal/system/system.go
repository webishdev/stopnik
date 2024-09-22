package system

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var signalLock = &sync.Mutex{}
var sigs chan os.Signal
var signalSingleton *byte

var startTime = time.Now()

var exitFunc = os.Exit

// GetSignalChannel returns the signal channel registered for notifications about syscall.SIGINT and syscall.SIGTERM.
func GetSignalChannel() chan os.Signal {
	signalLock.Lock()
	defer signalLock.Unlock()
	if signalSingleton == nil {
		sigs = make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		signalSingleton = new(byte)
	}
	return sigs
}

// GetStartTime provides the start time of the application.
func GetStartTime() time.Time {
	return startTime
}

// CriticalError handles a critical error, prints a message and exists the application with a error code.
func CriticalError(err error) {
	if err != nil {
		errorMessage := fmt.Sprintf("An critical error occurred: %v", err)
		println(errorMessage)
		exitFunc(1)
	}
}

// Error handles an error, prints a message and sends syscall.SIGTERM signal to teardown the application.
func Error(err error) {
	if err != nil {
		errorMessage := fmt.Sprintf("An error occurred: %v", err)
		println(errorMessage)
		GetSignalChannel() <- syscall.SIGTERM
	}
}

// ConfigureExit allows to overwrite the used os.Exit function. Used in tests.
func ConfigureExit(newFunc func(code int)) {
	exitFunc = newFunc
}
