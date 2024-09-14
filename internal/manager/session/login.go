package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"sync"
	"time"
)

type LoginSession struct {
	Id        string
	Username  string
	StartTime time.Time
}

type loginManager struct {
	config            *config.Config
	loginSessionStore *store.ExpiringStore[LoginSession]
}

type LoginManager[T LoginSession] interface {
	Manager[T]
	CloseSession(id string, all bool)
	SearchSession(username string) ([]*T, bool)
}

var loginSessionManagerLock = &sync.Mutex{}
var loginSessionManagerSingleton LoginManager[LoginSession]

func GetLoginSessionManagerInstance() LoginManager[LoginSession] {
	loginSessionManagerLock.Lock()
	defer loginSessionManagerLock.Unlock()
	if loginSessionManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		duration := time.Minute * time.Duration(currentConfig.GetSessionTimeoutSeconds())
		loginSessionStore := store.NewTimedStore[LoginSession](duration)
		loginSessionManagerSingleton = &loginManager{
			config:            currentConfig,
			loginSessionStore: &loginSessionStore,
		}
	}
	return loginSessionManagerSingleton
}

func (loginManager *loginManager) StartSession(loginSession *LoginSession) {
	loginSessionStore := *loginManager.loginSessionStore
	loginSession.StartTime = time.Now()
	loginSessionStore.Set(loginSession.Id, loginSession)
}

func (loginManager *loginManager) GetSession(id string) (*LoginSession, bool) {
	loginSessionStore := *loginManager.loginSessionStore
	return loginSessionStore.Get(id)
}

func (loginManager *loginManager) DeleteSession(id string) {
	loginSessionStore := *loginManager.loginSessionStore
	loginSessionStore.Delete(id)
}

func (loginManager *loginManager) CloseSession(id string, all bool) {
	loginSessionStore := *loginManager.loginSessionStore
	loginSession, loginSessionExists := loginSessionStore.Get(id)
	if loginSessionExists {
		log.Debug("Closing main login session with id %s", id)
		loginSessionStore.Delete(id)
		if all {
			username := loginSession.Username
			var userSessionIds []string
			for _, otherSession := range loginSessionStore.GetValues() {
				if otherSession.Username == username && otherSession.Id != id {
					userSessionIds = append(userSessionIds, otherSession.Id)
				}
			}
			for _, otherSessionId := range userSessionIds {
				log.Debug("Closing login session with id %s", otherSessionId)
				loginSessionStore.Delete(otherSessionId)
			}
		}
	}

}

func (loginManager *loginManager) SearchSession(username string) ([]*LoginSession, bool) {
	loginSessionStore := *loginManager.loginSessionStore
	var userSessions []*LoginSession
	exists := false
	for _, otherSession := range loginSessionStore.GetValues() {
		if otherSession.Username == username {
			userSessions = append(userSessions, otherSession)
			exists = true
		}
	}
	return userSessions, exists
}
