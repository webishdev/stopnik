package http

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/http"
	"stopnik/internal/config"
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
	value, err := cookieManager.generateCookieValue(username)
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
		return cookieManager.validateCookieValue(cookie)
	}
}

func (cookieManager *CookieManager) validateCookieValue(cookie *http.Cookie) (*config.User, bool) {
	token, err := jwt.Parse([]byte(cookie.Value), jwt.WithKey(jwa.HS256, []byte(cookieManager.config.GetServerSecret())))
	if err != nil {
		return &config.User{}, false
	}

	// https://stackoverflow.com/a/61284284/4094586
	username, exists := token.PrivateClaims()["username"]
	log.Debug("foo %s", username)
	if !exists {
		return &config.User{}, false
	}
	user, userExists := cookieManager.config.GetUser(fmt.Sprintf("%v", username))
	return user, userExists
}

func (cookieManager *CookieManager) generateCookieValue(username string) (string, error) {
	token, builderError := jwt.NewBuilder().Claim("username", username).Build()
	if builderError != nil {
		return "", builderError
	}

	tokenString, tokenError := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte(cookieManager.config.GetServerSecret())))
	if tokenError != nil {
		return "", tokenError
	}

	return string(tokenString), nil
}
