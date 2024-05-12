package store

import (
	"stopnik/assert"
	"stopnik/internal/config"
	"testing"
)

func Test_Session(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testConfig := &config.Config{}
		sessionManager := NewSessionManager(testConfig)

		authSession := &AuthSession{
			Id:                  "foo",
			Redirect:            "bar",
			AuthURI:             "moo",
			CodeChallenge:       "123",
			CodeChallengeMethod: "S256",
			ResponseType:        "token",
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

		assert.Equal(t, session, authSession)
	})

	t.Run("invalid", func(t *testing.T) {
		testConfig := &config.Config{}
		sessionManager := NewSessionManager(testConfig)

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
