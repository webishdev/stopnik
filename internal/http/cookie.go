package http

import (
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/crypto"
	"stopnik/log"
)

func DeleteCookie(config *config.Config) http.Cookie {
	authCookieName := config.GetAuthCookieName()
	return http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func CreateCookie(config *config.Config, username string) (http.Cookie, error) {
	authCookieName := config.GetAuthCookieName()
	log.Debug("Creating %s cookie", authCookieName)
	value, err := crypto.EncryptString(username, config.GetServerSecret())
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

func ValidateCookie(currentConfig *config.Config, r *http.Request) (*config.User, bool) {
	authCookieName := currentConfig.GetAuthCookieName()
	log.Debug("Validating %s cookie", authCookieName)
	cookie, cookieError := r.Cookie(authCookieName)
	if cookieError != nil {
		return &config.User{}, false
	} else {
		username, err := crypto.DecryptString(cookie.Value, currentConfig.GetServerSecret())
		if err != nil {
			return &config.User{}, false
		}
		user, userExists := currentConfig.GetUser(username)
		return user, userExists
	}
}
