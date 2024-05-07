package handler

import (
	"net/http"
	"slices"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"stopnik/log"
)

type RevokeHandler struct {
	config       *config.Config
	validator    *validation.RequestValidator
	tokenManager *store.TokenManager
}

func CreateRevokeHandler(config *config.Config, validator *validation.RequestValidator, tokenManager *store.TokenManager) *RevokeHandler {
	return &RevokeHandler{
		config:       config,
		validator:    validator,
		tokenManager: tokenManager,
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
			_, scopes, userExists := handler.tokenManager.ValidateAccessToken(r)
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
			_, tokenExists := handler.tokenManager.GetRefreshToken(token)

			if tokenExists {
				handler.tokenManager.RevokeRefreshToken(token)
			}
		} else {
			_, tokenExists := handler.tokenManager.GetAccessToken(token)

			if tokenExists {
				handler.tokenManager.RevokeAccessToken(token)
			}
		}

		w.WriteHeader(http.StatusOK)

	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
