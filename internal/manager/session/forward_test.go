package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"reflect"
	"testing"
)

func Test_ForwardSession(t *testing.T) {
	testConfig := &config.Config{}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	t.Run("Forward session found", func(t *testing.T) {
		sessionManager := GetForwardSessionManagerInstance()

		forwardSession := &ForwardSession{
			Id: "foo",
		}
		sessionManager.StartSession(forwardSession)

		session, sessionExits := sessionManager.GetSession("foo")

		if !sessionExits {
			t.Errorf("expected forward session to exists")
		}

		if !reflect.DeepEqual(session, forwardSession) {
			t.Errorf("assertion error, %v != %v", session, forwardSession)
		}
	})

	t.Run("Forward session not found", func(t *testing.T) {
		sessionManager := GetForwardSessionManagerInstance()

		forwardSession := &ForwardSession{
			Id: "foo",
		}
		sessionManager.StartSession(forwardSession)

		_, sessionExits := sessionManager.GetSession("bar")

		if sessionExits {
			t.Errorf("expected forward session not to exists")
		}
	})
}
