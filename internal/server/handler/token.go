package handler

import (
	"crypto/sha512"
	"fmt"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/pkce"
	"stopnik/internal/server/auth"
	"stopnik/internal/server/json"
	"stopnik/internal/store"
	"stopnik/log"
)

type TokenHandler struct {
	config            *config.Config
	authSessionStore  *store.Store[store.AuthSession]
	accessTokenStore  *store.Store[oauth2.AccessToken]
	refreshTokenStore *store.Store[oauth2.RefreshToken]
}

func CreateTokenHandler(config *config.Config, authSessionStore *store.Store[store.AuthSession], tokenStores *store.TokenStores[oauth2.AccessToken, oauth2.RefreshToken]) *TokenHandler {
	return &TokenHandler{
		config:            config,
		authSessionStore:  authSessionStore,
		accessTokenStore:  tokenStores.AccessTokenStore,
		refreshTokenStore: tokenStores.RefreshTokenStore,
	}
}

func (handler *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		client, validClientCredentials := auth.ClientCredentials(handler.config, r)
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
		if !validClientCredentials {
			ForbiddenHandler(w, r)
			return
		}

		grantTypeValue := r.PostFormValue(oauth2.ParameterGrantType)
		grantType, grantTypeExists := oauth2.GrantTypeFromString(grantTypeValue)
		if !grantTypeExists {
			ForbiddenHandler(w, r)
			return
		}

		var scopes []string
		var username string

		if grantType == oauth2.GtAuthorizationCode {

			codeVerifier := r.PostFormValue(pkce.ParameterCodeVerifier) // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
			if codeVerifier != "" {
				code := r.PostFormValue(oauth2.ParameterCode)
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
			usernameFrom := r.PostFormValue(oauth2.ParameterUsername)
			passwordForm := r.PostFormValue(oauth2.ParameterPassword)

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

		if grantType == oauth2.GtRefreshToken && client.GetRefreshTTL() <= 0 {
			ForbiddenHandler(w, r)
			return
		} else if grantType == oauth2.GtRefreshToken && client.GetRefreshTTL() > 0 {
			refreshTokenForm := r.PostFormValue(oauth2.ParameterRefreshToken)
			refreshToken, refreshTokenExists := handler.refreshTokenStore.Get(refreshTokenForm)
			if !refreshTokenExists {
				ForbiddenHandler(w, r)
				return
			}

			if refreshToken.ClientId != client.Id {
				ForbiddenHandler(w, r)
				return
			}
		}

		accessTokenResponse := oauth2.CreateAccessTokenResponse(handler.accessTokenStore, handler.refreshTokenStore, username, client, scopes)

		jsonError := json.SendJson(accessTokenResponse, w)
		if jsonError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
