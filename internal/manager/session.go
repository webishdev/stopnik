package manager

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/store"
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
	authSessionStore *store.ExpiringStore[AuthSession]
}

func NewSessionManager(config *config.Config) *SessionManager {
	authSessionStore := store.NewDefaultTimedStore[AuthSession]()
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
