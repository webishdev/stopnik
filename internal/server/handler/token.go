package handler

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/oauth2"
	oauth2parameters "stopnik/internal/oauth2/parameters"
	"stopnik/internal/pkce"
	pkceParameters "stopnik/internal/pkce/parameters"
	"stopnik/internal/server/auth"
	"stopnik/internal/store"
)

type TokenHandler struct {
	config           *config.Config
	authSessionStore *store.Store[store.AuthSession]
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateTokenHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession], accessTokenStore *store.Store[oauth2.AccessToken]) *TokenHandler {
	return &TokenHandler{
		config:           config,
		authSessionStore: authSessionStore,
		accessTokenStore: accessTokenStore,
	}
}

func (handler *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
	if r.Method == http.MethodPost {
		for k, v := range r.Header {
			log.Printf("%v: %v\n", k, v)
		}

		client, validClientCredentials := auth.ClientCredentials(handler.config, r)
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
		if !validClientCredentials {
			ForbiddenHandler(w, r)
			return
		}

		grantTypeValue := r.PostFormValue(oauth2parameters.GrantType)
		grantType, grantTypeExists := oauth2.GrantTypeFromString(grantTypeValue)
		if !grantTypeExists {
			ForbiddenHandler(w, r)
			return
		}

		var scopes []string
		var username string

		if grantType == oauth2.GtAuthorizationCode {

			codeVerifier := r.PostFormValue(pkceParameters.CodeVerifier) // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
			if codeVerifier != "" {
				code := r.PostFormValue(oauth2parameters.Code)
				authSession, authSessionExists := handler.authSessionStore.Get(code)
				if !authSessionExists {
					ForbiddenHandler(w, r)
					return
				}
				codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authSession.CodeChallengeMethod)
				if !codeChallengeMethodExists {
					ForbiddenHandler(w, r)
					return
				}
				validPKCE := pkce.ValidatePKCE(codeChallengeMethod, authSession.CodeChallenge, codeVerifier)
				if !validPKCE {
					ForbiddenHandler(w, r)
					return
				}
				scopes = authSession.Scopes
				username = authSession.Username
			}

		}

		if grantType == oauth2.GtPassword {
			usernameFrom := r.PostFormValue(oauth2parameters.Username)
			passwordForm := r.PostFormValue(oauth2parameters.Password)

			user, exists := handler.config.GetUser(usernameFrom)
			if !exists {
				InternalServerErrorHandler(w, r)
				return
			}
			passwordHash := fmt.Sprintf("%x", sha512.Sum512([]byte(passwordForm)))
			if passwordHash != user.Password {
				ForbiddenHandler(w, r)
				return
			}
			username = usernameFrom
		}

		accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, username, client.Id, scopes, client.GetAccessTTL())

		bytes, tokenMarshalError := json.Marshal(accessTokenResponse)
		if tokenMarshalError != nil {
			return
		}

		w.Header().Set(httpHeader.ContentType, httpHeader.ContentTypeJSON)
		_, writeError := w.Write(bytes)
		if writeError != nil {
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
