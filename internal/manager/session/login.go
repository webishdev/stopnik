package session

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"sync"
	"time"
)

type LoginSession struct {
	Id       string
	Username string
}

type LoginManager struct {
	config            *config.Config
	loginSessionStore *store.ExpiringStore[LoginSession]
}

var loginSessionManagerLock = &sync.Mutex{}
var loginSessionManagerSingleton *LoginManager

func GetLoginSessionManagerInstance() Manager[LoginSession] {
	loginSessionManagerLock.Lock()
	defer loginSessionManagerLock.Unlock()
	if loginSessionManagerSingleton == nil {
		currentConfig := config.GetConfigInstance()
		duration := time.Minute * time.Duration(currentConfig.GetSessionTimeoutSeconds())
		loginSessionStore := store.NewTimedStore[LoginSession](duration)
		loginSessionManagerSingleton = &LoginManager{
			config:            currentConfig,
			loginSessionStore: &loginSessionStore,
		}
	}
	return loginSessionManagerSingleton
}

func (loginManager *LoginManager) StartSession(loginSession *LoginSession) {
	loginSessionStore := *loginManager.loginSessionStore
	loginSessionStore.Set(loginSession.Id, loginSession)
}

func (loginManager *LoginManager) GetSession(id string) (*LoginSession, bool) {
	loginSessionStore := *loginManager.loginSessionStore
	return loginSessionStore.Get(id)
}

func (loginManager *LoginManager) CloseSession(id string, all bool) {
	loginSessionStore := *loginManager.loginSessionStore
	loginSession, loginSessionExists := loginSessionStore.Get(id)
	if loginSessionExists {
		log.Info("Closing main login session with id %s", id)
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
				log.Info("Closing login session with id %s", otherSessionId)
				loginSessionStore.Delete(otherSessionId)
			}
		}
	}

}
