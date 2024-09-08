package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"reflect"
	"testing"
)

func Test_LoginSession(t *testing.T) {
	testConfig := &config.Config{}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	t.Run("Login session found", func(t *testing.T) {
		sessionManager := GetLoginSessionManagerInstance()

		loginSession := &LoginSession{
			Id: "foo",
		}
		sessionManager.StartSession(loginSession)

		session, sessionExits := sessionManager.GetSession("foo")

		if !sessionExits {
			t.Errorf("expected login session to exists")
		}

		if !reflect.DeepEqual(session, loginSession) {
			t.Errorf("assertion error, %v != %v", session, loginSession)
		}
	})

	t.Run("Login session not found", func(t *testing.T) {
		sessionManager := GetLoginSessionManagerInstance()

		loginSession := &LoginSession{
			Id: "foo",
		}
		sessionManager.StartSession(loginSession)

		_, sessionExits := sessionManager.GetSession("bar")

		if sessionExits {
			t.Errorf("expected login session not to exists")
		}
	})

	t.Run("Login session all closed", func(t *testing.T) {
		sessionManager := GetLoginSessionManagerInstance()

		loginSessionFoo := &LoginSession{
			Id:       "foo",
			Username: "foo",
		}
		sessionManager.StartSession(loginSessionFoo)

		loginSessionBar := &LoginSession{
			Id:       "bar",
			Username: "foo",
		}
		sessionManager.StartSession(loginSessionBar)

		_, sessionExits := sessionManager.GetSession("foo")

		if !sessionExits {
			t.Errorf("expected login session to exists")
		}

		_, sessionExits = sessionManager.GetSession("bar")

		if !sessionExits {
			t.Errorf("expected login session to exists")
		}

		sessionManager.CloseSession("foo", true)

		_, sessionExits = sessionManager.GetSession("foo")

		if sessionExits {
			t.Errorf("expected login session not to exists")
		}

		_, sessionExits = sessionManager.GetSession("bar")

		if sessionExits {
			t.Errorf("expected login session not to exists")
		}
	})

	t.Run("Search login session", func(t *testing.T) {
		sessionManager := GetLoginSessionManagerInstance()

		loginSessionFoo := &LoginSession{
			Id:       "foo",
			Username: "foo",
		}
		sessionManager.StartSession(loginSessionFoo)

		loginSessionBar := &LoginSession{
			Id:       "bar",
			Username: "foo",
		}
		sessionManager.StartSession(loginSessionBar)

		_, sessionExits := sessionManager.SearchSession("foo")

		if !sessionExits {
			t.Errorf("expected login session to exists")
		}

		_, sessionExits = sessionManager.SearchSession("bar")

		if sessionExits {
			t.Errorf("expected login session to not exists")
		}
	})
}
