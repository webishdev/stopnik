package handler

import (
	"crypto/sha512"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
)

type LoginHandler struct {
	config           *config.Config
	authSessionStore *store.Store[store.AuthSession]
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateLoginHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession], accessTokenStore *store.Store[oauth2.AccessToken]) *LoginHandler {
	return &LoginHandler{
		config:           config,
		authSessionStore: authSessionStore,
		accessTokenStore: accessTokenStore,
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
		authSession, exists := handler.authSessionStore.Get(authSessionForm)
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
		if passwordHash != user.Password {
			w.Header().Set("Location", authSession.AuthURI)
			w.WriteHeader(http.StatusSeeOther)
		}

		cookie := http.Cookie{
			Name:     "STOPIK_AUTH",
			Value:    "Hello world!",
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		http.SetCookie(w, &cookie)

		redirectURL, urlParseError := url.Parse(authSession.Redirect)
		if urlParseError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		query := redirectURL.Query()
		if authSession.ResponseType == string(oauth2.RtToken) {
			accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore)
			query.Add("access_token", string(accessTokenResponse.AccessToken))
			query.Add("token_type", string(accessTokenResponse.TokenType))
			query.Add("expires_in", fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
		} else {
			query.Add("code", authSessionForm)
		}

		redirectURL.RawQuery = query.Encode()

		w.Header().Set("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)
	} else {
		NotFoundHandler(w, r)
	}
}
