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
	"slices"
	"strings"
	"time"
)

// tokenGrant holds the values of a validated grant, which are used to create the tokens.
type tokenGrant struct {
	scopes            []string
	username          string
	requestedClaims   *oidc.ClaimsParameter
	nonce             string
	authorizationCode string
	grantId           string
	authTime          time.Time
}

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

	var grant *tokenGrant
	var grantError *oauth2.TokenErrorResponseParameter
	switch grantType {
	case oauth2.GtAuthorizationCode:
		grant, grantError = h.authorizationCodeGrant(r, client)
	case oauth2.GtPassword:
		grant, grantError = h.passwordGrant(r)
	case oauth2.GtClientCredentials:
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
		grant = &tokenGrant{scopes: strings.Split(r.PostFormValue(oauth2.ParameterScope), " ")}
	case oauth2.GtRefreshToken:
		grant, grantError = h.refreshTokenGrant(r, client)
	default:
		grantError = &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnsupportedGrandType}
	}
	if grantError != nil {
		oauth2.TokenErrorResponseHandler(w, r, grantError)
		return
	}
	scopes := grant.scopes

	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	disallowedScopes := h.config.GetDisallowedScopes(client, scopes)
	if len(disallowedScopes) > 0 {
		log.Error("Scopes %v are not allowed for client %s", disallowedScopes, client.Id)
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidScope})
		return
	}

	var accessTokenResponse oauth2.AccessTokenResponse
	if grantType == oauth2.GtClientCredentials {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
		// A refresh token SHOULD NOT be included for the client credentials grant
		accessTokenResponse = h.tokenManager.CreateAccessTokenResponseWithoutRefreshToken(r, grant.username, client, &grant.authTime, scopes, grant.requestedClaims, grant.nonce)
	} else {
		accessTokenResponse = h.tokenManager.CreateAccessTokenResponse(r, grant.username, client, &grant.authTime, scopes, grant.requestedClaims, grant.nonce, grant.authorizationCode, grant.grantId)
	}

	jsonError := internalHttp.SendJson(accessTokenResponse, w, r)
	if jsonError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
		return
	}
}

// authorizationCodeGrant validates the authorization code grant.
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
func (h *Handler) authorizationCodeGrant(r *http.Request, client *config.Client) (*tokenGrant, *oauth2.TokenErrorResponseParameter) {
	code := r.PostFormValue(oauth2.ParameterCode)
	// Taking the code removes it, so a code can only be redeemed once, even for concurrent requests
	authorizationCode, authorizationCodeExists := h.authorizationCodeManager.TakeSession(code)
	if !authorizationCodeExists {
		h.tokenManager.RevokeAccessTokenByAuthorizationCode(code)
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
	// The code must have been issued to the authenticated client
	if authorizationCode.ClientId != client.Id {
		log.Error("Authorization code issued for client %s was used by client %s", authorizationCode.ClientId, client.Id)
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	// The redirect_uri must be identical to the one used in the authorization request
	redirectUri := r.PostFormValue(oauth2.ParameterRedirectUri)
	if redirectUri != authorizationCode.Redirect {
		log.Error("Invalid redirect URI %s for authorization code of client %s", redirectUri, client.Id)
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	// Codes are only issued after the user logged in, checked anyway as defence in depth
	if authorizationCode.Username == "" {
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	codeVerifier := r.PostFormValue(pkce.ParameterCodeVerifier) // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
	// When a code challenge was provided, the code verifier is mandatory, a code verifier without code challenge is rejected
	if authorizationCode.CodeChallenge == "" && codeVerifier == "" {
		return &tokenGrant{
			scopes:            authorizationCode.Scopes,
			username:          authorizationCode.Username,
			nonce:             authorizationCode.Nonce,
			requestedClaims:   authorizationCode.RequestedClaims,
			authTime:          authorizationCode.AuthTime,
			authorizationCode: code,
		}, nil
	}
	if authorizationCode.CodeChallenge == "" || !pkce.IsValidCodeVerifier(codeVerifier) {
		log.Error("Missing, unexpected or invalid code verifier for client %s", client.Id)
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}
	codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authorizationCode.CodeChallengeMethod)
	if !codeChallengeMethodExists || !pkce.ValidatePKCE(codeChallengeMethod, authorizationCode.CodeChallenge, codeVerifier) {
		log.Error("Code verifier does not match the code challenge for client %s", client.Id)
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	return &tokenGrant{
		scopes:            authorizationCode.Scopes,
		username:          authorizationCode.Username,
		nonce:             authorizationCode.Nonce,
		requestedClaims:   authorizationCode.RequestedClaims,
		authTime:          authorizationCode.AuthTime,
		authorizationCode: code,
	}, nil
}

// passwordGrant validates the resource owner password credentials grant.
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
func (h *Handler) passwordGrant(r *http.Request) (*tokenGrant, *oauth2.TokenErrorResponseParameter) {
	usernameFrom := r.PostFormValue(oauth2.ParameterUsername)
	passwordForm := r.PostFormValue(oauth2.ParameterPassword)
	scopeForm := r.PostFormValue(oauth2.ParameterScope)

	user, exists := h.validator.ValidateUserPassword(r, usernameFrom, passwordForm)
	if !exists {
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest}
	}
	return &tokenGrant{
		scopes:   strings.Split(scopeForm, " "),
		username: user.Username,
	}, nil
}

// refreshTokenGrant validates the refresh token grant.
// https://datatracker.ietf.org/doc/html/rfc6749#section-6
func (h *Handler) refreshTokenGrant(r *http.Request, client *config.Client) (*tokenGrant, *oauth2.TokenErrorResponseParameter) {
	if client.GetRefreshTTL() <= 0 {
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest}
	}

	refreshTokenForm := r.PostFormValue(oauth2.ParameterRefreshToken)

	// The client is verified before the refresh token is consumed,
	// so a client presenting the refresh token of another client can not invalidate it
	existingRefreshToken, existingRefreshTokenExists := h.tokenManager.GetRefreshToken(refreshTokenForm)
	if existingRefreshTokenExists && existingRefreshToken.ClientId != client.Id {
		log.Error("Refresh token issued for client %s was used by client %s", existingRefreshToken.ClientId, client.Id)
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-6
	// The requested scope must not include any scope not originally granted, when omitted the original scope is used
	scopeForm := r.PostFormValue(oauth2.ParameterScope)
	var requestedScopes []string
	if scopeForm != "" && existingRefreshTokenExists {
		requestedScopes = strings.Split(scopeForm, " ")
		for _, requestedScope := range requestedScopes {
			if requestedScope != "" && !slices.Contains(existingRefreshToken.Scopes, requestedScope) {
				log.Error("Scope %s was not granted originally for client %s", requestedScope, client.Id)
				return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidScope}
			}
		}
	}

	// https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
	// Refresh tokens are rotated, a new refresh token is issued and the used one becomes invalid,
	// presenting a used refresh token again revokes all tokens of its grant
	refreshToken, refreshTokenExists := h.tokenManager.TakeRefreshToken(refreshTokenForm)
	if !refreshTokenExists || refreshToken.ClientId != client.Id {
		return nil, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant}
	}

	scopes := refreshToken.Scopes
	if len(requestedScopes) > 0 {
		scopes = requestedScopes
	}

	return &tokenGrant{
		scopes:          scopes,
		username:        refreshToken.Username,
		requestedClaims: refreshToken.RequestedClaims,
		authTime:        refreshToken.AuthTime,
		grantId:         refreshToken.GrantId,
	}, nil
}
