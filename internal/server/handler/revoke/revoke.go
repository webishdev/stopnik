package revoke

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"slices"
)

type Handler struct {
	config       *config.Config
	validator    *validation.RequestValidator
	tokenManager *manager.TokenManager
	errorHandler *error.Handler
}

func NewRevokeHandler(config *config.Config, validator *validation.RequestValidator, tokenManager *manager.TokenManager) *Handler {
	return &Handler{
		config:       config,
		validator:    validator,
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7009
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// Check client credentials
		client, _, validClientCredentials := h.validator.ValidateClientCredentials(r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			authorizationHeader := r.Header.Get(internalHttp.Authorization)
			_, scopes, userExists := h.tokenManager.ValidateAccessToken(authorizationHeader)
			if !userExists {
				oauth2.TokenErrorStatusResponseHandler(w, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}

			hasRevokeScope := slices.Contains(scopes, h.config.GetRevokeScope())

			if !hasRevokeScope {
				oauth2.TokenErrorStatusResponseHandler(w, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		} else {
			if !client.Revoke {
				// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1
				oauth2.TokenErrorStatusResponseHandler(w, http.StatusServiceUnavailable, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnsupportedTokenType})
				return
			}
		}

		token := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHintParameter := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		tokenTypeHint, tokenTypeHintExists := oauth2.IntrospectTokenTypeFromString(tokenTypeHintParameter)

		if !tokenTypeHintExists {
			accessTokenRevoked := h.revokeAccessToken(token)
			if !accessTokenRevoked {
				h.revokeRefreshToken(token)
			}
		} else if tokenTypeHint == oauth2.ItAccessToken {
			h.revokeAccessToken(token)
		} else if tokenTypeHint == oauth2.ItRefreshToken {
			h.revokeRefreshToken(token)
		}

		w.WriteHeader(http.StatusOK)

	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (h *Handler) revokeRefreshToken(token string) bool {
	refreshToken, tokenExists := h.tokenManager.GetRefreshToken(token)

	if tokenExists {
		h.tokenManager.RevokeRefreshToken(refreshToken)
	}

	return tokenExists
}

func (h *Handler) revokeAccessToken(token string) bool {
	accessToken, tokenExists := h.tokenManager.GetAccessToken(token)

	if tokenExists {
		h.tokenManager.RevokeAccessToken(accessToken)
	}

	return tokenExists
}
