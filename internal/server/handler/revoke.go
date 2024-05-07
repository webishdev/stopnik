package handler

import (
	"net/http"
	"slices"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/auth"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"stopnik/log"
)

type RevokeHandler struct {
	config            *config.Config
	validator         *validation.RequestValidator
	accessTokenStore  *store.Store[oauth2.AccessToken]
	refreshTokenStore *store.Store[oauth2.RefreshToken]
}

func CreateRevokeHandler(config *config.Config, validator *validation.RequestValidator, tokenStores *store.TokenStores[oauth2.AccessToken, oauth2.RefreshToken]) *RevokeHandler {
	return &RevokeHandler{
		config:            config,
		validator:         validator,
		accessTokenStore:  tokenStores.AccessTokenStore,
		refreshTokenStore: tokenStores.RefreshTokenStore,
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7009
func (handler *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// Check client credentials
		client, validClientCredentials := handler.validator.ValidateClientCredentials(r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			_, scopes, userExists := auth.AccessToken(handler.config, handler.accessTokenStore, r)
			if !userExists {
				ForbiddenHandler(w, r)
				return
			}

			hasRevokeScope := slices.Contains(scopes, handler.config.GetRevokeScope())

			if !hasRevokeScope {
				ForbiddenHandler(w, r)
				return
			}
		} else {
			if !client.Revoke {
				ForbiddenHandler(w, r)
				return
			}
		}

		token := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHint := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		if tokenTypeHint == "refresh_token" {
			_, tokenExists := handler.refreshTokenStore.Get(token)

			if tokenExists {
				handler.refreshTokenStore.Delete(token)
			}
		} else {
			_, tokenExists := handler.accessTokenStore.Get(token)

			if tokenExists {
				handler.accessTokenStore.Delete(token)
			}
		}

		w.WriteHeader(http.StatusOK)

	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
