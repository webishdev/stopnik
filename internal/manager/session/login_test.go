package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/store"
	"reflect"
	"sync"
	"testing"
	"time"
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

func Test_LoginSessionTimeout(t *testing.T) {
	testConfig := &config.Config{Server: config.Server{SessionTimeoutSeconds: 120}}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	var mockedTime = time.Date(1979, 1, 17, 15, 0, 0, 0, time.Local)
	var mockedTickerChannel = make(chan time.Time, 1)
	rwMutex := &sync.RWMutex{}
	now := func() time.Time {
		rwMutex.RLock()
		defer rwMutex.RUnlock()
		return mockedTime
	}
	addTime := func(d time.Duration) {
		rwMutex.Lock()
		defer rwMutex.Unlock()
		mockedTime = mockedTime.Add(d)
	}
	tickerChannel := func() <-chan time.Time {
		return mockedTickerChannel
	}

	sessionManager := newLoginManager(testConfig, store.NewTimerWithClock(now, tickerChannel))
	sessionManager.StartSession(&LoginSession{Id: "foo", Username: "foo"})

	addTime(time.Second * time.Duration(119))
	if _, sessionExists := sessionManager.GetSession("foo"); !sessionExists {
		t.Error("expected login session to exist before the session timeout")
	}

	addTime(time.Second * time.Duration(2))
	if _, sessionExists := sessionManager.GetSession("foo"); sessionExists {
		t.Error("expected login session to be gone after the configured timeout in seconds")
	}
}
