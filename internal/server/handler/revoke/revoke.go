package revoke

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/manager/token"
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
	tokenManager *token.Manager
	errorHandler *error.Handler
}

func NewRevokeHandler(validator *validation.RequestValidator, tokenManager *token.Manager) *Handler {
	currentConfig := config.GetConfigInstance()
	return &Handler{
		config:       currentConfig,
		validator:    validator,
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

// Implements https://datatracker.ietf.org/doc/html/rfc7009
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {

		// requestingClient is nil, when the caller used an access token with the revoke scope
		var requestingClient *config.Client

		// Check client credentials
		client, _, validClientCredentials := h.validator.ValidateClientCredentials(r)
		if !validClientCredentials {

			// Fall back to access token with scopes
			validAccessToken, valid := h.tokenManager.ValidateAccessTokenRequest(r)
			if !valid {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}

			scopes := validAccessToken.Scopes

			hasRevokeScope := slices.Contains(scopes, h.config.GetRevokeScope())

			// The scope based revocation is the administrative path, which allows to revoke tokens of other clients,
			// so the client of the access token must be allowed to revoke tokens as well
			if !hasRevokeScope || !validAccessToken.Client.Revoke {
				oauth2.TokenErrorStatusResponseHandler(w, r, http.StatusUnauthorized, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		} else {
			// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
			// Every client, also public clients, may revoke tokens which were issued to it
			requestingClient = client
		}

		tokenParameter := r.PostFormValue(oauth2.ParameterToken)
		tokenTypeHintParameter := r.PostFormValue(oauth2.ParameterTokenTypeHint)

		tokenTypeHint, tokenTypeHintExists := oauth2.IntrospectTokenTypeFromString(tokenTypeHintParameter)

		if !tokenTypeHintExists {
			accessTokenFound := h.revokeAccessToken(requestingClient, tokenParameter)
			if !accessTokenFound {
				h.revokeRefreshToken(requestingClient, tokenParameter)
			}
		} else if tokenTypeHint == oauth2.ItAccessToken {
			h.revokeAccessToken(requestingClient, tokenParameter)
		} else if tokenTypeHint == oauth2.ItRefreshToken {
			h.revokeRefreshToken(requestingClient, tokenParameter)
		}

		// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
		// The server responds with 200 also for invalid tokens or tokens of other clients
		w.WriteHeader(http.StatusOK)

	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

// revokeRefreshToken revokes the refresh token and all access tokens which were issued for the same grant.
// When a requesting client is given, only refresh tokens of this client are revoked.
// Returns whether the refresh token was found.
func (h *Handler) revokeRefreshToken(requestingClient *config.Client, token string) bool {
	refreshToken, tokenExists := h.tokenManager.GetRefreshToken(token)

	if tokenExists && isIssuedTo(requestingClient, refreshToken.ClientId) {
		h.tokenManager.RevokeRefreshToken(refreshToken)
		h.tokenManager.RevokeGrant(refreshToken.GrantId)
	}

	return tokenExists
}

// revokeAccessToken revokes the access token.
// When a requesting client is given, only access tokens of this client are revoked.
// Returns whether the access token was found.
func (h *Handler) revokeAccessToken(requestingClient *config.Client, token string) bool {
	accessToken, tokenExists := h.tokenManager.GetAccessToken(token)

	if tokenExists && isIssuedTo(requestingClient, accessToken.ClientId) {
		h.tokenManager.RevokeAccessToken(accessToken)
	}

	return tokenExists
}

// isIssuedTo returns whether a token issued to the given client id may be revoked by the requesting client.
// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
// The server verifies whether the token was issued to the client making the revocation request.
func isIssuedTo(requestingClient *config.Client, clientId string) bool {
	if requestingClient == nil {
		return true
	}
	if requestingClient.Id != clientId {
		log.Warn("Client %s tried to revoke a token issued to another client", requestingClient.Id)
		return false
	}
	return true
}
