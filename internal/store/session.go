package store

import (
	"stopnik/internal/config"
)

type SessionManager struct {
	config           *config.Config
	authSessionStore *Store[AuthSession]
}

func NewSessionManager(config *config.Config) *SessionManager {
	return &SessionManager{
		config:           config,
		authSessionStore: NewCache[AuthSession](),
	}
}

func (sessionManager *SessionManager) StartSession(authSession *AuthSession) {
	sessionManager.authSessionStore.Set(authSession.Id, authSession)
}

func (sessionManager *SessionManager) GetSession(id string) (*AuthSession, bool) {
	return sessionManager.authSessionStore.Get(id)
}
