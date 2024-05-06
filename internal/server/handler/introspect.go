package handler

import (
	"encoding/json"
	"net/http"
	"slices"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/auth"
	"stopnik/internal/store"
	"stopnik/log"
	"strings"
)

// as described in https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type introspectResponse struct {
	Active    bool             `json:"active"`
	Scope     string           `json:"scope,omitempty"`
	ClientId  string           `json:"client_id,omitempty"`
	Username  string           `json:"username,omitempty"`
	TokenType oauth2.TokenType `json:"token_type,omitempty"`
}

type IntrospectHandler struct {
	config            *config.Config
	accessTokenStore  *store.Store[oauth2.AccessToken]
	refreshTokenStore *store.Store[oauth2.RefreshToken]
}

func CreateIntrospectHandler(config *config.Config, tokenStores *store.TokenStores[oauth2.AccessToken, oauth2.RefreshToken]) *IntrospectHandler {
	return &IntrospectHandler{
		config:            config,
		accessTokenStore:  tokenStores.AccessTokenStore,
		refreshTokenStore: tokenStores.RefreshTokenStore,
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7662
func (handler *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// Check client credentials
		client, validClientCredentials := auth.ClientCredentials(handler.config, r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			_, scopes, userExists := auth.AccessToken(handler.config, handler.accessTokenStore, r)
			if !userExists {
				ForbiddenHandler(w, r)
				return
			}

			hasIntrospectScope := slices.Contains(scopes, handler.config.GetIntrospectScope())

			if !hasIntrospectScope {
				ForbiddenHandler(w, r)
				return
			}
		} else {
			if !client.Introspect {
				ForbiddenHandler(w, r)
				return
			}
		}

		token := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHint := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		introspectResponse := introspectResponse{}

		if tokenTypeHint == "refresh_token" {
			refreshToken, tokenExists := handler.refreshTokenStore.Get(token)

			introspectResponse.Active = tokenExists

			if tokenExists {
				introspectResponse.Username = refreshToken.Username
				introspectResponse.ClientId = refreshToken.ClientId
				introspectResponse.Scope = strings.Join(refreshToken.Scopes, " ")
			}
		} else {
			accessToken, tokenExists := handler.accessTokenStore.Get(token)

			introspectResponse.Active = tokenExists

			if tokenExists {
				introspectResponse.Username = accessToken.Username
				introspectResponse.ClientId = accessToken.ClientId
				introspectResponse.Scope = strings.Join(accessToken.Scopes, " ")
				introspectResponse.TokenType = accessToken.TokenType
			}
		}

		bytes, introspectMarshalError := json.Marshal(introspectResponse)
		if introspectMarshalError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		w.Header().Set(internalHttp.ContentType, internalHttp.ContentTypeJSON)
		_, writeError := w.Write(bytes)
		if writeError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
