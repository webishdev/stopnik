package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/store"
	"sync"
)

type ForwardSession struct {
	Id                    string
	CodeChallengeVerifier string
	RedirectUri           string
	State                 string
}

type ForwardManager struct {
	config              *config.Config
	forwardSessionStore *store.ExpiringStore[ForwardSession]
}

var forwardSessionManagerLock = &sync.Mutex{}
var forwardSessionManagerSingleton *ForwardManager

func GetForwardSessionManagerInstance() Manager[ForwardSession] {
	forwardSessionManagerLock.Lock()
	defer forwardSessionManagerLock.Unlock()
	if forwardSessionManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		forwardSessionStore := store.NewDefaultTimedStore[ForwardSession]()
		forwardSessionManagerSingleton = &ForwardManager{
			config:              currentConfig,
			forwardSessionStore: &forwardSessionStore,
		}
	}
	return forwardSessionManagerSingleton
}

func (forwardManager *ForwardManager) StartSession(forwardSession *ForwardSession) {
	authSessionStore := *forwardManager.forwardSessionStore
	authSessionStore.Set(forwardSession.Id, forwardSession)
}

func (forwardManager *ForwardManager) GetSession(id string) (*ForwardSession, bool) {
	forwardSessionStore := *forwardManager.forwardSessionStore
	return forwardSessionStore.Get(id)
}

func (forwardManager *ForwardManager) DeleteSession(id string) {
	forwardSessionStore := *forwardManager.forwardSessionStore
	forwardSessionStore.Delete(id)
}
