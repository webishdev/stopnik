package handler

import (
	"net/http"
	"slices"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/validation"
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
	config       *config.Config
	validator    *validation.RequestValidator
	tokenManager *store.TokenManager
}

func CreateIntrospectHandler(config *config.Config, validator *validation.RequestValidator, tokenManager *store.TokenManager) *IntrospectHandler {
	return &IntrospectHandler{
		config:       config,
		validator:    validator,
		tokenManager: tokenManager,
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7662
func (handler *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// Check client credentials
		client, validClientCredentials := handler.validator.ValidateClientCredentials(r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			authorizationHeader := r.Header.Get(internalHttp.Authorization)
			_, scopes, userExists := handler.tokenManager.ValidateAccessToken(authorizationHeader)
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
			refreshToken, tokenExists := handler.tokenManager.GetRefreshToken(token)

			introspectResponse.Active = tokenExists

			if tokenExists {
				introspectResponse.Username = refreshToken.Username
				introspectResponse.ClientId = refreshToken.ClientId
				introspectResponse.Scope = strings.Join(refreshToken.Scopes, " ")
			}
		} else {
			accessToken, tokenExists := handler.tokenManager.GetAccessToken(token)

			introspectResponse.Active = tokenExists

			if tokenExists {
				introspectResponse.Username = accessToken.Username
				introspectResponse.ClientId = accessToken.ClientId
				introspectResponse.Scope = strings.Join(accessToken.Scopes, " ")
				introspectResponse.TokenType = accessToken.TokenType
			}
		}

		jsonError := internalHttp.SendJson(introspectResponse, w)
		if jsonError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
