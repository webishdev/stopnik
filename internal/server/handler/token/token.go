package token

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	config                   *config.Config
	validator                *validation.RequestValidator
	authorizationCodeManager session.Manager[session.AuthorizationCode]
	tokenManager             *token.Manager
	errorHandler             *error.Handler
}

func NewTokenHandler(validator *validation.RequestValidator, authorizationCodeManager session.Manager[session.AuthorizationCode], tokenManager *token.Manager) *Handler {
	return &Handler{
		config:                   config.GetConfigInstance(),
		validator:                validator,
		authorizationCodeManager: authorizationCodeManager,
		tokenManager:             tokenManager,
		errorHandler:             error.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		h.handlePostRequest(w, r)
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (h *Handler) handlePostRequest(w http.ResponseWriter, r *http.Request) {
	client, fallbackUsed, validClientCredentials := h.validator.ValidateClientCredentials(r)
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	if !validClientCredentials {
		httpStatus := http.StatusUnauthorized
		if fallbackUsed {
			httpStatus = http.StatusBadRequest
		}
		oauth2.TokenErrorStatusResponseHandler(w, r, httpStatus, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidClient})
		return
	}

	grantTypeValue := r.PostFormValue(oauth2.ParameterGrantType)
	grantType, grantTypeExists := oauth2.GrantTypeFromString(grantTypeValue)
	if !grantTypeExists {
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
		return
	}

	if !client.IsGrantTypeAllowed(grantType) {
		log.Error("Grant type %s is not allowed for client %s", grantType, client.Id)
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnauthorizedClient})
		return
	}

	var scopes []string
	var username string
	var requestedClaims *oidc.ClaimsParameter
	nonce := ""
	authCode := ""
	grantId := ""
	var authTime time.Time

	if grantType == oauth2.GtAuthorizationCode {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
		code := r.PostFormValue(oauth2.ParameterCode)
		// Taking the code removes it, so a code can only be redeemed once, even for concurrent requests
		authorizationCode, authorizationCodeExists := h.authorizationCodeManager.TakeSession(code)
		if !authorizationCodeExists {
			h.tokenManager.RevokeAccessTokenByAuthorizationCode(code)
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}

		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
		// The code must have been issued to the authenticated client
		if authorizationCode.ClientId != client.Id {
			log.Error("Authorization code issued for client %s was used by client %s", authorizationCode.ClientId, client.Id)
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}

		// The redirect_uri must be identical to the one used in the authorization request
		redirectUri := r.PostFormValue(oauth2.ParameterRedirectUri)
		if redirectUri != authorizationCode.Redirect {
			log.Error("Invalid redirect URI %s for authorization code of client %s", redirectUri, client.Id)
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}

		// Codes are only issued after the user logged in, checked anyway as defence in depth
		if authorizationCode.Username == "" {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}

		codeVerifier := r.PostFormValue(pkce.ParameterCodeVerifier) // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
		// https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
		// When a code challenge was provided, the code verifier is mandatory
		if authorizationCode.CodeChallenge != "" && codeVerifier == "" {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}
		if codeVerifier != "" {
			codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authorizationCode.CodeChallengeMethod)
			if !codeChallengeMethodExists {
				oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
			validPKCE := pkce.ValidatePKCE(codeChallengeMethod, authorizationCode.CodeChallenge, codeVerifier)
			if !validPKCE {
				oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		}

		scopes = authorizationCode.Scopes
		username = authorizationCode.Username
		nonce = authorizationCode.Nonce
		requestedClaims = authorizationCode.RequestedClaims
		authTime = authorizationCode.AuthTime
		authCode = code
	} else if grantType == oauth2.GtPassword {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
		usernameFrom := r.PostFormValue(oauth2.ParameterUsername)
		passwordForm := r.PostFormValue(oauth2.ParameterPassword)
		scopeForm := r.PostFormValue(oauth2.ParameterScope)

		user, exists := h.validator.ValidateUserPassword(usernameFrom, passwordForm)
		if !exists {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}
		scopes = strings.Split(scopeForm, " ")
		username = user.Username
	} else if grantType == oauth2.GtClientCredentials {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
		scopeForm := r.PostFormValue(oauth2.ParameterScope)

		scopes = strings.Split(scopeForm, " ")
	} else if grantType == oauth2.GtRefreshToken && client.GetRefreshTTL() <= 0 {
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
		return
	} else if grantType == oauth2.GtRefreshToken && client.GetRefreshTTL() > 0 {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-6
		refreshTokenForm := r.PostFormValue(oauth2.ParameterRefreshToken)
		// https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
		// Refresh tokens are rotated, a new refresh token is issued and the used one becomes invalid
		refreshToken, refreshTokenExists := h.tokenManager.TakeRefreshToken(refreshTokenForm)
		if !refreshTokenExists {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}

		if refreshToken.ClientId != client.Id {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}

		username = refreshToken.Username
		scopes = refreshToken.Scopes
		authTime = refreshToken.AuthTime
		requestedClaims = refreshToken.RequestedClaims
		grantId = refreshToken.GrantId
	} else {
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnsupportedGrandType})
		return
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	disallowedScopes := h.config.GetDisallowedScopes(client, scopes)
	if len(disallowedScopes) > 0 {
		log.Error("Scopes %v are not allowed for client %s", disallowedScopes, client.Id)
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidScope})
		return
	}

	accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, username, client, &authTime, scopes, requestedClaims, nonce, authCode, grantId)

	jsonError := internalHttp.SendJson(accessTokenResponse, w, r)
	if jsonError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
		return
	}
}
