package handler

import (
	"crypto/sha512"
	"fmt"
	"log"
	"net/http"
	"tiny-gate/internal/cache"
	"tiny-gate/internal/config"
)

type LoginHandler struct {
	config *config.Config
	cache  *cache.Cache[cache.AuthSession]
}

func CreateLoginHandler(config *config.Config, cache *cache.Cache[cache.AuthSession]) *LoginHandler {
	return &LoginHandler{
		config: config,
		cache:  cache,
	}
}

func (handler *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		parseError := r.ParseForm()
		if parseError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		authSessionForm := r.Form.Get("auth_session")
		authSession, exists := handler.cache.Get(authSessionForm)
		if !exists {
			InternalServerErrorHandler(w, r)
			return
		}
		// When login invalid
		// https://en.wikipedia.org/wiki/Post/Redirect/Get
		// redirect with Status 303
		// When login valid
		user, exists := handler.config.GetUser(username)
		if !exists {
			InternalServerErrorHandler(w, r)
			return
		}
		passwordHash := fmt.Sprintf("%x", sha512.Sum512([]byte(password)))
		if passwordHash == user.Password {

			cookie := http.Cookie{
				Name:     "STOPIK_AUTH",
				Value:    "Hello world!",
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}

			http.SetCookie(w, &cookie)

			w.Header().Set("Location", authSession.Redirect)
			w.WriteHeader(http.StatusFound)
		}
		w.Header().Set("Location", authSession.AuthURI)
		w.WriteHeader(http.StatusSeeOther)
	} else {
		NotFoundHandler(w, r)
	}
}
