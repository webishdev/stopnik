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
	"time"
)

// response as described in https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type response struct {
	Active     bool             `json:"active"`
	Scope      string           `json:"scope,omitempty"`
	ClientId   string           `json:"client_id,omitempty"`
	Username   string           `json:"username,omitempty"`
	TokenType  oauth2.TokenType `json:"token_type,omitempty"`
	Expiration int64            `json:"exp,omitempty"`
	IssuedAt   int64            `json:"iat,omitempty"`
	Subject    string           `json:"sub,omitempty"`
	Audience   []string         `json:"aud,omitempty"`
	Issuer     string           `json:"iss,omitempty"`
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
			validAccessToken, valid := h.tokenManager.ValidateAccessTokenRequest(r)
			if !valid {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidClient})
				return
			}

			scopes := validAccessToken.Scopes

			hasIntrospectScope := slices.Contains(scopes, h.config.GetIntrospectScope())

			if !hasIntrospectScope {
				// https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusForbidden, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInsufficientScope})
				return
			}
		} else {
			// https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
			// Public clients can not authenticate, so they could use the endpoint to scan for valid tokens
			if client.GetClientType() != oauth2.CtConfidential {
				log.Error("Public client %s is not allowed to introspect tokens", client.Id)
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidClient})
				return
			}
			// A client with the introspect flag, e.g. a resource server, may introspect tokens of all clients
			if !client.Introspect {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusForbidden, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnauthorizedClient})
				return
			}
		}

		tokenParameter := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHintParameter := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		tokenTypeHint, tokenTypeHintExists := oauth2.IntrospectTokenTypeFromString(tokenTypeHintParameter)

		introspectResponse := response{}

		if !tokenTypeHintExists {
			accessTokenExists := h.checkAccessToken(tokenParameter, &introspectResponse)
			if !accessTokenExists {
				h.checkRefreshToken(tokenParameter, &introspectResponse)
			}
		} else if tokenTypeHint == oauth2.ItAccessToken {
			h.checkAccessToken(tokenParameter, &introspectResponse)
		} else if tokenTypeHint == oauth2.ItRefreshToken {
			h.checkRefreshToken(tokenParameter, &introspectResponse)
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
		h.setTokenDetails(introspectResponse, refreshToken.ClientId, refreshToken.Username, refreshToken.IssuedAt, refreshToken.ExpiresAt)
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
		h.setTokenDetails(introspectResponse, accessToken.ClientId, accessToken.Username, accessToken.IssuedAt, accessToken.ExpiresAt)
	}

	return tokenExists
}

// setTokenDetails sets the optional details of an active token, as described in
// https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
func (h *Handler) setTokenDetails(introspectResponse *response, clientId string, username string, issuedAt time.Time, expiresAt time.Time) {
	introspectResponse.Subject = username
	introspectResponse.Issuer = h.config.GetIssuer()
	if !issuedAt.IsZero() {
		introspectResponse.IssuedAt = issuedAt.Unix()
	}
	if !expiresAt.IsZero() {
		introspectResponse.Expiration = expiresAt.Unix()
	}
	client, clientExists := h.config.GetClient(clientId)
	if clientExists {
		introspectResponse.Audience = client.GetAudience()
	}
}
