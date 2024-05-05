package handler

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/url"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/oauth2"
	oauth2Parameters "stopnik/internal/oauth2/parameters"
	"stopnik/internal/store"
	"stopnik/log"
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
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		parseError := r.ParseForm()
		if parseError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
		username := r.Form.Get("stopnik_username")
		password := r.Form.Get("stopnik_password")
		authSessionForm := r.Form.Get("stopnik_auth_session")
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
			w.Header().Set(httpHeader.Location, authSession.AuthURI)
			w.WriteHeader(http.StatusSeeOther)
		}

		cookie, err := CreateCookie(handler.config, user.Username)
		if err != nil {
			InternalServerErrorHandler(w, r)
			return
		}
		authSession.Username = user.Username
		http.SetCookie(w, &cookie)

		redirectURL, urlParseError := url.Parse(authSession.Redirect)
		if urlParseError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		query := redirectURL.Query()
		if authSession.ResponseType == string(oauth2.RtToken) {
			client, exists := handler.config.GetClient(authSession.ClientId)
			if !exists {
				InternalServerErrorHandler(w, r)
				return
			}
			accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, user.Username, client, authSession.Scopes)
			query.Add(oauth2Parameters.AccessToken, accessTokenResponse.AccessTokenKey)
			query.Add(oauth2Parameters.TokenType, string(accessTokenResponse.TokenType))
			query.Add(oauth2Parameters.ExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
		} else {
			query.Add(oauth2Parameters.Code, authSessionForm)
		}

		if authSession.State != "" {
			query.Add(oauth2Parameters.State, authSession.State)
		}

		redirectURL.RawQuery = query.Encode()

		w.Header().Set(httpHeader.Location, redirectURL.String())
		w.WriteHeader(http.StatusFound)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
