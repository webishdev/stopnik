package store

import (
	"github.com/webishdev/stopnik/internal/config"
)

type AuthSession struct {
	Id                  string
	Redirect            string
	AuthURI             string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseType        string
	Username            string
	ClientId            string
	Scopes              []string
	State               string
}

type SessionManager struct {
	config           *config.Config
	authSessionStore *Store[AuthSession]
}

func NewSessionManager(config *config.Config) *SessionManager {
	authSessionStore := NewDefaultTimedStore[AuthSession]()
	return &SessionManager{
		config:           config,
		authSessionStore: &authSessionStore,
	}
}

func (sessionManager *SessionManager) StartSession(authSession *AuthSession) {
	authSessionStore := *sessionManager.authSessionStore
	authSessionStore.Set(authSession.Id, authSession)
}

func (sessionManager *SessionManager) GetSession(id string) (*AuthSession, bool) {
	authSessionStore := *sessionManager.authSessionStore
	return authSessionStore.Get(id)
}
