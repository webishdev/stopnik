package system

import (
	"errors"
	"os"
	"sync"
	"testing"
)

func Test_System(t *testing.T) {
	t.Run("Critical error", func(t *testing.T) {
		var exitCode *int
		exitFunc = func(code int) {
			exitCode = &code
		}

		CriticalError(errors.New("foo"))

		if exitCode == nil || *exitCode != 1 {
			t.Errorf("Expected exit code 1, got %d", exitCode)
		}
	})

	t.Run("Error", func(t *testing.T) {
		var exitCode *int
		exitFunc = func(code int) {
			exitCode = &code
		}

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
	})
}
