package http

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"time"
)

type Now func() time.Time

type CookieManager struct {
	config *config.Config
	now    Now
}

func NewCookieManager(config *config.Config) *CookieManager {
	return newCookieManagerWithTime(config, time.Now)
}

func newCookieManagerWithTime(config *config.Config, now Now) *CookieManager {
	return &CookieManager{config: config, now: now}
}

func (cookieManager *CookieManager) CreateMessageCookie(message string) http.Cookie {
	log.Debug("Creating %s message cookie", message)
	return http.Cookie{
		Name:     "stopnik_message",
		Value:    message,
		Path:     "/",
		MaxAge:   5,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (cookieManager *CookieManager) GetMessageCookieValue(r *http.Request) string {
	cookie, cookieError := r.Cookie("stopnik_message")
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
	token, err := jwt.Parse([]byte(cookie.Value), jwt.WithKey(jwa.HS256, []byte(cookieManager.config.GetServerSecret())))
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

	tokenString, tokenError := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte(cookieManager.config.GetServerSecret())))
	if tokenError != nil {
		return "", tokenError
	}

	return string(tokenString), nil
}
