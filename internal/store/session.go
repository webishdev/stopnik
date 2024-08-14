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
	return &SessionManager{
		config:           config,
		authSessionStore: NewStore[AuthSession](),
	}
}

func (sessionManager *SessionManager) StartSession(authSession *AuthSession) {
	sessionManager.authSessionStore.Set(authSession.Id, authSession)
}

func (sessionManager *SessionManager) GetSession(id string) (*AuthSession, bool) {
	return sessionManager.authSessionStore.Get(id)
}
