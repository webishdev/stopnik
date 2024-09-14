package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/store"
	"sync"
	"time"
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
	AuthTime            time.Time
}

type AuthManager struct {
	config           *config.Config
	authSessionStore *store.ExpiringStore[AuthSession]
}

var authSessionManagerLock = &sync.Mutex{}
var authSessionManagerSingleton *AuthManager

func GetAuthSessionManagerInstance() Manager[AuthSession] {
	authSessionManagerLock.Lock()
	defer authSessionManagerLock.Unlock()
	if authSessionManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		authSessionStore := store.NewDefaultTimedStore[AuthSession]()
		authSessionManagerSingleton = &AuthManager{
			config:           currentConfig,
			authSessionStore: &authSessionStore,
		}
	}
	return authSessionManagerSingleton
}

func (authManager *AuthManager) StartSession(authSession *AuthSession) {
	authSessionStore := *authManager.authSessionStore
	authSessionStore.Set(authSession.Id, authSession)
}

func (authManager *AuthManager) GetSession(id string) (*AuthSession, bool) {
	authSessionStore := *authManager.authSessionStore
	return authSessionStore.Get(id)
}
