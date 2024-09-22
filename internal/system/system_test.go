package system

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func Test_CriticalError(t *testing.T) {
	var exitCode *int
	ConfigureExit(func(code int) {
		exitCode = &code
	})

	CriticalError(errors.New("foo"))

	if exitCode == nil || *exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func Test_Error(t *testing.T) {
	var exitCode *int
	ConfigureExit(func(code int) {
		exitCode = &code
	})

	wg := sync.WaitGroup{}
	var signal *os.Signal

	s := GetSignalChannel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		current := <-s
		signal = &current
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		Error(errors.New("foo"))
	}()

	wg.Wait()

	if exitCode != nil {
		t.Error("Exit should not be called")
	}

	if signal == nil {
		t.Error("Signal should not be called")
	}
}

func Test_StartTime(t *testing.T) {
	currentTime := time.Now()
	currentStartTime := GetStartTime()

	if !(currentTime.After(currentStartTime) || currentStartTime.Equal(currentTime)) {
		t.Error("start time should match")
	}
}
