package manager

import (
	internalConfig "github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/store"
)

type AuthSession struct {
	Id                  string
	Redirect            string
	AuthURI             string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseTypes       []oauth2.ResponseType
	Username            string
	ClientId            string
	Scopes              []string
	State               string
	Nonce               string // OpenId Connect
}

type SessionManager struct {
	config           *internalConfig.Config
	authSessionStore *store.ExpiringStore[AuthSession]
}

func NewSessionManager() *SessionManager {
	config := internalConfig.GetConfigInstance()
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
