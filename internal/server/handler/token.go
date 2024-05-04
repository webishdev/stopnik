package handler

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/pkce"
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

		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
		clientId, clientSecret, ok := r.BasicAuth()
		if !ok {
			// Check fallback
			clientId = r.PostFormValue("client_id")
			clientSecret = r.PostFormValue("client_secret")
		}

		client, clientExists := handler.config.GetClient(clientId)
		if !clientExists {
			ForbiddenHandler(w, r)
			return
		}

		secretHash := fmt.Sprintf("%x", sha512.Sum512([]byte(clientSecret)))

		if secretHash != client.Secret {
			ForbiddenHandler(w, r)
			return
		}

		grantTypeValue := r.PostFormValue("grant_type")
		grantType, grantTypeExists := oauth2.GrantTypeFromString(grantTypeValue)
		if !grantTypeExists {
			ForbiddenHandler(w, r)
			return
		}

		var scopes []string

		if grantType == oauth2.GtAuthorizationCode {

			codeVerifier := r.PostFormValue("code_verifier") // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
			if codeVerifier != "" {
				code := r.PostFormValue("code")
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
			}

		}

		if grantType == oauth2.GtPassword {
			username := r.PostFormValue("username")
			password := r.PostFormValue("password")

			user, exists := handler.config.GetUser(username)
			if !exists {
				InternalServerErrorHandler(w, r)
				return
			}
			passwordHash := fmt.Sprintf("%x", sha512.Sum512([]byte(password)))
			if passwordHash != user.Password {
				ForbiddenHandler(w, r)
				return
			}
		}

		accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, client.Id, scopes, client.GetAccessTTL())

		bytes, tokenMarshalError := json.Marshal(accessTokenResponse)
		if tokenMarshalError != nil {
			return
		}
		_, writeError := w.Write(bytes)
		if writeError != nil {
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
