package http

import (
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/crypto"
	"stopnik/log"
)

type CookieManager struct {
	config *config.Config
}

func NewCookieManager(config *config.Config) *CookieManager {
	return &CookieManager{config: config}
}

func (cookieManager *CookieManager) DeleteCookie() http.Cookie {
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

func (cookieManager *CookieManager) CreateCookie(username string) (http.Cookie, error) {
	authCookieName := cookieManager.config.GetAuthCookieName()
	log.Debug("Creating %s cookie", authCookieName)
	value, err := crypto.EncryptString(username, cookieManager.config.GetServerSecret())
	if err != nil {
		return http.Cookie{}, err
	}
	return http.Cookie{
		Name:     authCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (cookieManager *CookieManager) ValidateCookie(r *http.Request) (*config.User, bool) {
	authCookieName := cookieManager.config.GetAuthCookieName()
	log.Debug("Validating %s cookie", authCookieName)
	cookie, cookieError := r.Cookie(authCookieName)
	if cookieError != nil {
		return &config.User{}, false
	} else {
		username, err := crypto.DecryptString(cookie.Value, cookieManager.config.GetServerSecret())
		if err != nil {
			return &config.User{}, false
		}
		user, userExists := cookieManager.config.GetUser(username)
		return user, userExists
	}
}
