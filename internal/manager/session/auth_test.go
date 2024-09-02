package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/oauth2"
	"reflect"
	"testing"
)

func Test_Session(t *testing.T) {
	testConfig := &config.Config{}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	t.Run("Session found", func(t *testing.T) {
		sessionManager := GetAuthSessionManagerInstance()

		authSession := &AuthSession{
			Id:                  "foo",
			Redirect:            "bar",
			AuthURI:             "moo",
			CodeChallenge:       "123",
			CodeChallengeMethod: "S256",
			ResponseTypes:       []oauth2.ResponseType{oauth2.RtToken},
			Username:            "alice",
			ClientId:            "example",
			Scopes:              []string{"abc", "def"},
			State:               "789",
		}
		sessionManager.StartSession(authSession)

		session, sessionExits := sessionManager.GetSession("foo")

		if !sessionExits {
			t.Errorf("expected session to exists")
		}

		if !reflect.DeepEqual(session, authSession) {
			t.Errorf("assertion error, %v != %v", session, authSession)
		}
	})

	t.Run("Session not found", func(t *testing.T) {
		sessionManager := GetAuthSessionManagerInstance()

		authSession := &AuthSession{
			Id:       "foo",
			Redirect: "bar",
		}
		sessionManager.StartSession(authSession)

		_, sessionExits := sessionManager.GetSession("bar")

		if sessionExits {
			t.Errorf("expected session not to exists")
		}
	})
}
