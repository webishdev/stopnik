package handler

import (
	"encoding/json"
	"net/http"
	"slices"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/oauth2"
	oauth2Parameters "stopnik/internal/oauth2/parameters"
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
	config           *config.Config
	accessTokenStore *store.Store[oauth2.AccessToken]
}

func CreateIntrospectHandler(config *config.Config, accessTokenStore *store.Store[oauth2.AccessToken]) *IntrospectHandler {
	return &IntrospectHandler{
		config:           config,
		accessTokenStore: accessTokenStore,
	}
}

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

			hasIntrospectScope := slices.Contains(scopes, "stopnik:introspect")

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

		token := r.PostFormValue(oauth2Parameters.Token)
		accessToken, tokenExists := handler.accessTokenStore.Get(token)

		introspectResponse := introspectResponse{
			Active: tokenExists,
		}

		if tokenExists {
			introspectResponse.Username = accessToken.Username
			introspectResponse.ClientId = accessToken.ClientId
			introspectResponse.Scope = strings.Join(accessToken.Scopes, " ")
			introspectResponse.TokenType = accessToken.TokenType
		}

		bytes, introspectMarshalError := json.Marshal(introspectResponse)
		if introspectMarshalError != nil {
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
