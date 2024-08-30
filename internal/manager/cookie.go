package manager

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"sync"
	"time"
)

type Now func() time.Time

type CookieManager struct {
	config      *config.Config
	keyFallback crypto.ServerSecretLoader
	now         Now
}

var cookieManagerLock = &sync.Mutex{}
var cookieManagerSingleton *CookieManager

func GetCookieManagerInstance() *CookieManager {
	cookieManagerLock.Lock()
	defer cookieManagerLock.Unlock()
	if cookieManagerSingleton == nil {
		cookieManagerSingleton = newCookieManagerWithTime(time.Now)
	}
	return cookieManagerSingleton
}

func newCookieManagerWithTime(now Now) *CookieManager {
	configInstance := config.GetConfigInstance()
	return &CookieManager{
		config:      configInstance,
		keyFallback: crypto.NewServerSecretLoader(),
		now:         now,
	}
}

func (cookieManager *CookieManager) CreateMessageCookie(message string) http.Cookie {
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

func (cookieManager *CookieManager) GetMessageCookieValue(r *http.Request) string {
	messageCookieName := cookieManager.config.GetMessageCookieName()
	cookie, cookieError := r.Cookie(messageCookieName)
	if cookieError != nil {
		return ""
	}
	return cookie.Value
}

func (cookieManager *CookieManager) DeleteAuthCookie() http.Cookie {
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

func (cookieManager *CookieManager) CreateAuthCookie(username string) (http.Cookie, error) {
	authCookieName := cookieManager.config.GetAuthCookieName()
	log.Debug("Creating %s auth cookie", authCookieName)
	value, err := cookieManager.generateCookieValue(username)
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

func (cookieManager *CookieManager) ValidateAuthCookie(r *http.Request) (*config.User, bool) {
	authCookieName := cookieManager.config.GetAuthCookieName()
	log.Debug("Validating %s cookie", authCookieName)
	cookie, cookieError := r.Cookie(authCookieName)
	if cookieError != nil {
		return &config.User{}, false
	} else {
		return cookieManager.validateCookieValue(cookie)
	}
}

func (cookieManager *CookieManager) validateCookieValue(cookie *http.Cookie) (*config.User, bool) {
	options := cookieManager.keyFallback.GetServerKey()
	token, err := jwt.Parse([]byte(cookie.Value), options)
	if err != nil {
		return &config.User{}, false
	}

	// https://stackoverflow.com/a/61284284/4094586
	username := token.Subject()
	user, userExists := cookieManager.config.GetUser(username)
	return user, userExists
}

func (cookieManager *CookieManager) generateCookieValue(username string) (string, error) {
	sessionTimeout := cookieManager.config.GetSessionTimeoutSeconds()
	token, builderError := jwt.NewBuilder().
		Subject(username).
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
