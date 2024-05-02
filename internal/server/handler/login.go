package handler

import (
	"log"
	"net/http"
	"tiny-gate/internal/cache"
)

type LoginHandler struct {
	cache *cache.Cache[cache.AuthSession]
}

func CreateLoginHandler(cache *cache.Cache[cache.AuthSession]) *LoginHandler {
	return &LoginHandler{
		cache: cache,
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
		if username == "foo" && password == "bar" {
			w.Header().Set("Location", authSession.Redirect)
			w.WriteHeader(http.StatusFound)
		}
		w.Header().Set("Location", authSession.AuthURI)
		w.WriteHeader(http.StatusSeeOther)
	} else {
		NotFoundHandler(w, r)
	}
}
