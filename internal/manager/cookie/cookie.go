package cookie

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"sync"
	"time"
)

type Now func() time.Time

type Manager struct {
	config       *config.Config
	loginSession session.Manager[session.LoginSession]
	keyFallback  crypto.ServerSecretLoader
	now          Now
}

var cookieManagerLock = &sync.Mutex{}
var cookieManagerSingleton *Manager

func GetCookieManagerInstance() *Manager {
	cookieManagerLock.Lock()
	defer cookieManagerLock.Unlock()
	if cookieManagerSingleton == nil {
		cookieManagerSingleton = newCookieManagerWithTime(time.Now)
	}
	return cookieManagerSingleton
}

func newCookieManagerWithTime(now Now) *Manager {
	configInstance := config.GetConfigInstance()
	return &Manager{
		config:       configInstance,
		loginSession: session.GetLoginSessionManagerInstance(),
		keyFallback:  crypto.NewServerSecretLoader(),
		now:          now,
	}
}

func (cookieManager *Manager) CreateMessageCookie(message string) http.Cookie {
	messageCookieName := cookieManager.config.GetMessageCookieName()
	log.Debug("Creating %s message cookie", message)
	return http.Cookie{
		Name:     messageCookieName,
		Value:    message,
		Path:     "/",
		MaxAge:   5,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (cookieManager *Manager) GetMessageCookieValue(r *http.Request) string {
	messageCookieName := cookieManager.config.GetMessageCookieName()
	cookie, cookieError := r.Cookie(messageCookieName)
	if cookieError != nil {
		return ""
	}
	return cookie.Value
}

func (cookieManager *Manager) DeleteAuthCookie() http.Cookie {
	authCookieName := cookieManager.config.GetAuthCookieName()
	return http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (cookieManager *Manager) CreateAuthCookie(username string, loginSessionId string) (http.Cookie, error) {
	authCookieName := cookieManager.config.GetAuthCookieName()
	log.Debug("Creating %s auth cookie", authCookieName)
	value, err := cookieManager.generateAuthCookieValue(username, loginSessionId)
	if err != nil {
		return http.Cookie{}, err
	}
	return http.Cookie{
		Name:     authCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   cookieManager.config.GetSessionTimeoutSeconds(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (cookieManager *Manager) ValidateAuthCookie(r *http.Request) (*config.User, *session.LoginSession, bool) {
	authCookieName := cookieManager.config.GetAuthCookieName()
	log.Debug("Validating %s auth cookie", authCookieName)
	cookie, cookieError := r.Cookie(authCookieName)
	if cookieError != nil {
		return &config.User{}, &session.LoginSession{}, false
	} else {
		return cookieManager.validateAuthCookieValue(cookie)
	}
}

func (cookieManager *Manager) validateAuthCookieValue(cookie *http.Cookie) (*config.User, *session.LoginSession, bool) {
	options := cookieManager.keyFallback.GetServerKey()
	token, err := jwt.Parse([]byte(cookie.Value), options)
	if err != nil {
		return &config.User{}, &session.LoginSession{}, false
	}

	loginClaim, loginClaimExists := token.Get("login")
	if !loginClaimExists {
		return &config.User{}, &session.LoginSession{}, false
	}

	loginSessionId := fmt.Sprintf("%s", loginClaim)

	loginSession, loginSessionExists := cookieManager.loginSession.GetSession(loginSessionId)
	if !loginSessionExists {
		return &config.User{}, &session.LoginSession{}, false
	}

	// https://stackoverflow.com/a/61284284/4094586
	username := token.Subject()
	user, userExists := cookieManager.config.GetUser(username)
	return user, loginSession, userExists
}

func (cookieManager *Manager) generateAuthCookieValue(username string, loginSessionId string) (string, error) {
	sessionTimeout := cookieManager.config.GetSessionTimeoutSeconds()
	token, builderError := jwt.NewBuilder().
		Subject(username).
		Claim("login", loginSessionId).
		Expiration(cookieManager.now().Add(time.Second * time.Duration(sessionTimeout))).
		Build()
	if builderError != nil {
		return "", builderError
	}

	options := cookieManager.keyFallback.GetServerKey()
	tokenString, tokenError := jwt.Sign(token, options)
	if tokenError != nil {
		return "", tokenError
	}

	return string(tokenString), nil
}
