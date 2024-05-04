package handler

import (
	"encoding/json"
	"net/http"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/store"
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
	if r.Method == http.MethodPost {
		authorization := r.Header.Get("Authorization")
		if authorization == "" || !strings.Contains(authorization, "Bearer ") {
			ForbiddenHandler(w, r)
			return
		}
		authorizationHeader := strings.Replace(authorization, "Bearer ", "", 1)
		_, authorizationHeaderExists := handler.accessTokenStore.Get(authorizationHeader)
		if !authorizationHeaderExists {
			ForbiddenHandler(w, r)
			return
		}

		token := r.PostFormValue("token")
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
		_, writeError := w.Write(bytes)
		if writeError != nil {
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
