package revoke

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
)

type RevokeHandler struct {
	config       *config.Config
	validator    *validation.RequestValidator
	tokenManager *store.TokenManager
	errorHandler *error.RequestHandler
}

func CreateRevokeHandler(config *config.Config, validator *validation.RequestValidator, tokenManager *store.TokenManager) *RevokeHandler {
	return &RevokeHandler{
		config:       config,
		validator:    validator,
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7009
func (handler *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

			hasRevokeScope := slices.Contains(scopes, handler.config.GetRevokeScope())

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
			accessTokenRevoked := handler.revokeAccessToken(token)
			if !accessTokenRevoked {
				handler.revokeRefreshToken(token)
			}
		} else if tokenTypeHint == oauth2.ItAccessToken {
			handler.revokeAccessToken(token)
		} else if tokenTypeHint == oauth2.ItRefreshToken {
			handler.revokeRefreshToken(token)
		}

		w.WriteHeader(http.StatusOK)

	} else {
		handler.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (handler *RevokeHandler) revokeRefreshToken(token string) bool {
	refreshToken, tokenExists := handler.tokenManager.GetRefreshToken(token)

	if tokenExists {
		handler.tokenManager.RevokeRefreshToken(refreshToken)
	}

	return tokenExists
}

func (handler *RevokeHandler) revokeAccessToken(token string) bool {
	accessToken, tokenExists := handler.tokenManager.GetAccessToken(token)

	if tokenExists {
		handler.tokenManager.RevokeAccessToken(accessToken)
	}

	return tokenExists
}
