package manager

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/store"
	"sync"
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
	config           *config.Config
	authSessionStore *store.ExpiringStore[AuthSession]
}

var sessionManagerLock = &sync.Mutex{}
var sessionManagerSingleton *SessionManager

func GetSessionManagerInstance() *SessionManager {
	sessionManagerLock.Lock()
	defer sessionManagerLock.Unlock()
	if sessionManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		authSessionStore := store.NewDefaultTimedStore[AuthSession]()
		sessionManagerSingleton = &SessionManager{
			config:           currentConfig,
			authSessionStore: &authSessionStore,
		}
	}
	return sessionManagerSingleton
}

func (sessionManager *SessionManager) StartSession(authSession *AuthSession) {
	authSessionStore := *sessionManager.authSessionStore
	authSessionStore.Set(authSession.Id, authSession)
}

func (sessionManager *SessionManager) GetSession(id string) (*AuthSession, bool) {
	authSessionStore := *sessionManager.authSessionStore
	return authSessionStore.Get(id)
}
