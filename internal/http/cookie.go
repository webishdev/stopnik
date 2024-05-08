package http

import (
	"github.com/golang-jwt/jwt/v5"
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
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return []byte(cookieManager.config.GetServerSecret()), nil
		})

		if err != nil {
			return &config.User{}, false
		}

		if !token.Valid {
			return &config.User{}, false
		}

		// https://stackoverflow.com/a/61284284/4094586
		claims := token.Claims.(jwt.MapClaims)
		username := claims["username"].(string)
		user, userExists := cookieManager.config.GetUser(username)
		return user, userExists
	}
}

func (cookieManager *CookieManager) generateCookieValue(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
		})

	tokenString, err := token.SignedString([]byte(cookieManager.config.GetServerSecret()))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
