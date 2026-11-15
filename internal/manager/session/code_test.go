package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/store"
	"reflect"
	"sync"
	"testing"
	"time"
)

func Test_AuthorizationCode(t *testing.T) {
	testConfig := &config.Config{}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	t.Run("Authorization code found", func(t *testing.T) {
		codeManager := GetAuthorizationCodeManagerInstance()

		authorizationCode := &AuthorizationCode{
			Code:                GenerateAuthorizationCode(),
			ClientId:            "example",
			Redirect:            "bar",
			Username:            "alice",
			Scopes:              []string{"abc", "def"},
			CodeChallenge:       "123",
			CodeChallengeMethod: "S256",
		}
		codeManager.StartSession(authorizationCode)

		session, sessionExits := codeManager.GetSession(authorizationCode.Code)

		if !sessionExits {
			t.Errorf("expected authorization code to exists")
		}

		if !reflect.DeepEqual(session, authorizationCode) {
			t.Errorf("assertion error, %v != %v", session, authorizationCode)
		}
	})

	t.Run("Authorization code not found", func(t *testing.T) {
		codeManager := GetAuthorizationCodeManagerInstance()

		_, sessionExits := codeManager.GetSession("bar")

		if sessionExits {
			t.Errorf("expected authorization code not to exists")
		}
	})

	t.Run("Authorization code can only be taken once", func(t *testing.T) {
		codeManager := GetAuthorizationCodeManagerInstance()

		authorizationCode := &AuthorizationCode{Code: GenerateAuthorizationCode()}
		codeManager.StartSession(authorizationCode)

		_, firstExists := codeManager.TakeSession(authorizationCode.Code)
		_, secondExists := codeManager.TakeSession(authorizationCode.Code)

		if !firstExists || secondExists {
			t.Errorf("expected authorization code to be taken exactly once")
		}
	})

	t.Run("Generated authorization codes are random", func(t *testing.T) {
		firstCode := GenerateAuthorizationCode()
		secondCode := GenerateAuthorizationCode()

		// 32 bytes encoded as base64 without padding
		if len(firstCode) != 43 || len(secondCode) != 43 {
			t.Errorf("expected authorization codes to have 43 characters, got %d and %d", len(firstCode), len(secondCode))
		}

		if firstCode == secondCode {
			t.Errorf("expected authorization codes to differ")
		}
	})

	t.Run("Authorization code expires after 60 seconds", func(t *testing.T) {
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

		codeManager := newCodeManager(store.NewTimerWithClock(now, tickerChannel))

		authorizationCode := &AuthorizationCode{Code: GenerateAuthorizationCode()}
		codeManager.StartSession(authorizationCode)

		addTime(time.Second * time.Duration(59))

		_, existsBeforeExpiry := codeManager.GetSession(authorizationCode.Code)
		if !existsBeforeExpiry {
			t.Errorf("expected authorization code to exist after 59 seconds")
		}

		addTime(time.Second * time.Duration(2))

		_, existsAfterExpiry := codeManager.TakeSession(authorizationCode.Code)
		if existsAfterExpiry {
			t.Errorf("expected authorization code to be rejected after 60 seconds")
		}
	})
}
