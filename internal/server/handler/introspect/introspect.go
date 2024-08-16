package introspect

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"slices"
	"strings"
)

// IntrospectResponse as described in https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type IntrospectResponse struct {
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
	errorHandler *error.RequestHandler
}

func CreateIntrospectHandler(config *config.Config, validator *validation.RequestValidator, tokenManager *store.TokenManager) *IntrospectHandler {
	return &IntrospectHandler{
		config:       config,
		validator:    validator,
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7662
func (handler *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// Check client credentials
		client, _, validClientCredentials := handler.validator.ValidateClientCredentials(r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			authorizationHeader := r.Header.Get(internalHttp.Authorization)
			_, scopes, userExists := handler.tokenManager.ValidateAccessToken(authorizationHeader)
			if !userExists {
				oauth2.TokenErrorStatusResponseHandler(w, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}

			hasIntrospectScope := slices.Contains(scopes, handler.config.GetIntrospectScope())

			if !hasIntrospectScope {
				oauth2.TokenErrorStatusResponseHandler(w, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		} else {
			if !client.Introspect {
				oauth2.TokenErrorStatusResponseHandler(w, http.StatusServiceUnavailable, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		}

		token := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHintParameter := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		tokenTypeHint, tokenTypeHintExists := oauth2.IntrospectTokenTypeFromString(tokenTypeHintParameter)

		introspectResponse := IntrospectResponse{}

		if !tokenTypeHintExists {
			accessTokenExists := handler.checkAccessToken(token, &introspectResponse)
			if !accessTokenExists {
				handler.checkRefreshToken(token, &introspectResponse)
			}
		} else if tokenTypeHint == oauth2.ItAccessToken {
			handler.checkAccessToken(token, &introspectResponse)
		} else if tokenTypeHint == oauth2.ItRefreshToken {
			handler.checkRefreshToken(token, &introspectResponse)
		}

		jsonError := internalHttp.SendJson(introspectResponse, w)
		if jsonError != nil {
			handler.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
	} else {
		handler.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (handler *IntrospectHandler) checkRefreshToken(token string, introspectResponse *IntrospectResponse) bool {
	refreshToken, tokenExists := handler.tokenManager.GetRefreshToken(token)

	introspectResponse.Active = tokenExists

	if tokenExists {
		introspectResponse.Username = refreshToken.Username
		introspectResponse.ClientId = refreshToken.ClientId
		introspectResponse.Scope = strings.Join(refreshToken.Scopes, " ")
	}

	return tokenExists
}

func (handler *IntrospectHandler) checkAccessToken(token string, introspectResponse *IntrospectResponse) bool {
	accessToken, tokenExists := handler.tokenManager.GetAccessToken(token)

	introspectResponse.Active = tokenExists

	if tokenExists {
		introspectResponse.Username = accessToken.Username
		introspectResponse.ClientId = accessToken.ClientId
		introspectResponse.Scope = strings.Join(accessToken.Scopes, " ")
		introspectResponse.TokenType = accessToken.TokenType
	}

	return tokenExists
}
