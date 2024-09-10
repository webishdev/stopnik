package introspect

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"slices"
	"strings"
)

// response as described in https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type response struct {
	Active    bool             `json:"active"`
	Scope     string           `json:"scope,omitempty"`
	ClientId  string           `json:"client_id,omitempty"`
	Username  string           `json:"username,omitempty"`
	TokenType oauth2.TokenType `json:"token_type,omitempty"`
}

type Handler struct {
	config       *config.Config
	validator    *validation.RequestValidator
	tokenManager *token.Manager
	errorHandler *error.Handler
}

func NewIntrospectHandler(validator *validation.RequestValidator, tokenManager *token.Manager) *Handler {
	currentConfig := config.GetConfigInstance()
	return &Handler{
		config:       currentConfig,
		validator:    validator,
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7662
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// Check client credentials
		client, _, validClientCredentials := h.validator.ValidateClientCredentials(r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			authorizationHeader := r.Header.Get(internalHttp.Authorization)
			_, _, scopes, valid := h.tokenManager.ValidateAccessToken(authorizationHeader)
			if !valid {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}

			hasIntrospectScope := slices.Contains(scopes, h.config.GetIntrospectScope())

			if !hasIntrospectScope {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		} else {
			if !client.Introspect {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusServiceUnavailable, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		}

		token := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHintParameter := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		tokenTypeHint, tokenTypeHintExists := oauth2.IntrospectTokenTypeFromString(tokenTypeHintParameter)

		introspectResponse := response{}

		if !tokenTypeHintExists {
			accessTokenExists := h.checkAccessToken(token, &introspectResponse)
			if !accessTokenExists {
				h.checkRefreshToken(token, &introspectResponse)
			}
		} else if tokenTypeHint == oauth2.ItAccessToken {
			h.checkAccessToken(token, &introspectResponse)
		} else if tokenTypeHint == oauth2.ItRefreshToken {
			h.checkRefreshToken(token, &introspectResponse)
		}

		jsonError := internalHttp.SendJson(introspectResponse, w, r)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (h *Handler) checkRefreshToken(token string, introspectResponse *response) bool {
	refreshToken, tokenExists := h.tokenManager.GetRefreshToken(token)

	introspectResponse.Active = tokenExists

	if tokenExists {
		introspectResponse.Username = refreshToken.Username
		introspectResponse.ClientId = refreshToken.ClientId
		introspectResponse.Scope = strings.Join(refreshToken.Scopes, " ")
	}

	return tokenExists
}

func (h *Handler) checkAccessToken(token string, introspectResponse *response) bool {
	accessToken, tokenExists := h.tokenManager.GetAccessToken(token)

	introspectResponse.Active = tokenExists

	if tokenExists {
		introspectResponse.Username = accessToken.Username
		introspectResponse.ClientId = accessToken.ClientId
		introspectResponse.Scope = strings.Join(accessToken.Scopes, " ")
		introspectResponse.TokenType = accessToken.TokenType
	}

	return tokenExists
}
