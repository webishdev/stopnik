package system

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var signalLock = &sync.Mutex{}
var sigs chan os.Signal
var signalSingleton *byte

func GetSignalChannel() chan os.Signal {
	signalLock.Lock()
	defer signalLock.Unlock()
	if signalSingleton == nil {
		sigs = make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	}
	return sigs
}

func CriticalError(err error) {
	if err != nil {
		errorMessage := fmt.Sprintf("An critical error occurred: %v", err)
		println(errorMessage)
		os.Exit(1)
	}
}

func Error(err error) {
	if err != nil {
		errorMessage := fmt.Sprintf("An error occurred: %v", err)
		println(errorMessage)
		GetSignalChannel() <- syscall.SIGTERM
	}
}
