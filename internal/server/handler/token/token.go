package token

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	validator          *validation.RequestValidator
	authSessionManager session.Manager[session.AuthSession]
	tokenManager       *token.Manager
	errorHandler       *error.Handler
}

func NewTokenHandler(validator *validation.RequestValidator, authSessionManager session.Manager[session.AuthSession], tokenManager *token.Manager) *Handler {
	return &Handler{
		validator:          validator,
		authSessionManager: authSessionManager,
		tokenManager:       tokenManager,
		errorHandler:       error.NewErrorHandler(),
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

	var scopes []string
	var username string
	nonce := ""
	authCode := ""
	var authTime time.Time

	if grantType == oauth2.GtAuthorizationCode {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
		code := r.PostFormValue(oauth2.ParameterCode)
		authSession, authSessionExists := h.authSessionManager.GetSession(code)
		if !authSessionExists {
			h.tokenManager.RevokeAccessTokenByAuthorizationCode(code)
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
			return
		}

		codeVerifier := r.PostFormValue(pkce.ParameterCodeVerifier) // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
		if codeVerifier != "" {
			codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authSession.CodeChallengeMethod)
			if !codeChallengeMethodExists {
				oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
			validPKCE := pkce.ValidatePKCE(codeChallengeMethod, authSession.CodeChallenge, codeVerifier)
			if !validPKCE {
				oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		}

		scopes = authSession.Scopes
		username = authSession.Username
		nonce = authSession.Nonce
		authTime = authSession.AuthTime
		authCode = code
		h.authSessionManager.DeleteSession(authSession.Id)
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
		refreshToken, refreshTokenExists := h.tokenManager.GetRefreshToken(refreshTokenForm)
		if !refreshTokenExists {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}

		if refreshToken.ClientId != client.Id {
			oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}

		username = refreshToken.Username
		scopes = refreshToken.Scopes
		authTime = refreshToken.AuthTime
	} else {
		oauth2.TokenErrorResponseHandler(w, r, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnsupportedGrandType})
		return
	}

	accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, username, client, &authTime, scopes, nonce, authCode)

	jsonError := internalHttp.SendJson(accessTokenResponse, w, r)
	if jsonError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
		return
	}
}
