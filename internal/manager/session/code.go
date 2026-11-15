package session

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/internal/system"
	"sync"
	"time"
)

// authorizationCodeLifetime defines how long an authorization code can be exchanged at the token endpoint.
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
// The authorization code MUST expire shortly after it is issued, a maximum lifetime of 10 minutes is RECOMMENDED.
const authorizationCodeLifetime = time.Second * time.Duration(60)

// AuthorizationCode holds everything the token endpoint needs to exchange an authorization code for tokens.
// It is created after the user was authenticated and is never changed afterward.
type AuthorizationCode struct {
	Code                string
	ClientId            string
	Redirect            string
	Username            string
	Scopes              []string
	Nonce               string // OpenId Connect
	RequestedClaims     *oidc.ClaimsParameter
	AuthTime            time.Time
	CodeChallenge       string
	CodeChallengeMethod string
}

type CodeManager struct {
	config                 *config.Config
	authorizationCodeStore *store.ExpiringStore[AuthorizationCode]
}

var authorizationCodeManagerLock = &sync.Mutex{}
var authorizationCodeManagerSingleton *CodeManager

func GetAuthorizationCodeManagerInstance() Manager[AuthorizationCode] {
	authorizationCodeManagerLock.Lock()
	defer authorizationCodeManagerLock.Unlock()
	if authorizationCodeManagerSingleton == nil {
		authorizationCodeManagerSingleton = newCodeManager(store.NewTimer())
	}
	return authorizationCodeManagerSingleton
}

func newCodeManager(timer *store.Timer) *CodeManager {
	currentConfig := config.GetConfigInstance()
	authorizationCodeStore := store.NewTimedStoreWithTimer[AuthorizationCode](authorizationCodeLifetime, timer)
	return &CodeManager{
		config:                 currentConfig,
		authorizationCodeStore: &authorizationCodeStore,
	}
}

// GenerateAuthorizationCode returns a new random value, which is used as authorization code.
// https://datatracker.ietf.org/doc/html/rfc6749#section-10.10
func GenerateAuthorizationCode() string {
	randomBytes := make([]byte, 32)
	_, randomError := rand.Read(randomBytes)
	if randomError != nil {
		system.CriticalError(randomError)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

func (codeManager *CodeManager) StartSession(authorizationCode *AuthorizationCode) {
	authorizationCodeStore := *codeManager.authorizationCodeStore
	authorizationCodeStore.Set(authorizationCode.Code, authorizationCode)
}

func (codeManager *CodeManager) GetSession(code string) (*AuthorizationCode, bool) {
	authorizationCodeStore := *codeManager.authorizationCodeStore
	return authorizationCodeStore.Get(code)
}

func (codeManager *CodeManager) DeleteSession(code string) {
	authorizationCodeStore := *codeManager.authorizationCodeStore
	authorizationCodeStore.Delete(code)
}

// TakeSession returns and removes the authorization code, so it can only be exchanged once.
func (codeManager *CodeManager) TakeSession(code string) (*AuthorizationCode, bool) {
	authorizationCodeStore := *codeManager.authorizationCodeStore
	return authorizationCodeStore.Take(code)
}

func (codeManager *CodeManager) SessionCount() int {
	authorizationCodeStore := *codeManager.authorizationCodeStore
	return authorizationCodeStore.Len()
}
