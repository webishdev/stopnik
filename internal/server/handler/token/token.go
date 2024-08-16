package token

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	serverHandler "github.com/webishdev/stopnik/internal/server/handler"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"strings"
)

type TokenHandler struct {
	validator      *validation.RequestValidator
	sessionManager *store.SessionManager
	tokenManager   *store.TokenManager
}

func CreateTokenHandler(validator *validation.RequestValidator, sessionManager *store.SessionManager, tokenManager *store.TokenManager) *TokenHandler {
	return &TokenHandler{
		validator:      validator,
		sessionManager: sessionManager,
		tokenManager:   tokenManager,
	}
}

func (handler *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		handler.handlePostRequest(w, r)
	} else {
		serverHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (handler *TokenHandler) handlePostRequest(w http.ResponseWriter, r *http.Request) {
	client, fallbackUsed, validClientCredentials := handler.validator.ValidateClientCredentials(r)
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
	if !validClientCredentials {
		httpStatus := http.StatusUnauthorized
		if fallbackUsed {
			httpStatus = http.StatusBadRequest
		}
		oauth2.TokenErrorStatusResponseHandler(w, httpStatus, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidClient})
		return
	}

	grantTypeValue := r.PostFormValue(oauth2.ParameterGrantType)
	grantType, grantTypeExists := oauth2.GrantTypeFromString(grantTypeValue)
	if !grantTypeExists {
		oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidGrant})
		return
	}

	var scopes []string
	var username string

	if grantType == oauth2.GtAuthorizationCode {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
		code := r.PostFormValue(oauth2.ParameterCode)
		authSession, authSessionExists := handler.sessionManager.GetSession(code)
		if !authSessionExists {
			oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}

		codeVerifier := r.PostFormValue(pkce.ParameterCodeVerifier) // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
		if codeVerifier != "" {
			codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authSession.CodeChallengeMethod)
			if !codeChallengeMethodExists {
				oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
			validPKCE := pkce.ValidatePKCE(codeChallengeMethod, authSession.CodeChallenge, codeVerifier)
			if !validPKCE {
				oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
				return
			}
		}

		scopes = authSession.Scopes
		username = authSession.Username
	} else if grantType == oauth2.GtPassword {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
		usernameFrom := r.PostFormValue(oauth2.ParameterUsername)
		passwordForm := r.PostFormValue(oauth2.ParameterPassword)
		scopeForm := r.PostFormValue(oauth2.ParameterScope)

		user, exists := handler.validator.ValidateUserPassword(usernameFrom, passwordForm)
		if !exists {
			oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}
		scopes = strings.Split(scopeForm, " ")
		username = user.Username
	} else if grantType == oauth2.GtClientCredentials {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
		scopeForm := r.PostFormValue(oauth2.ParameterScope)

		scopes = strings.Split(scopeForm, " ")
	} else if grantType == oauth2.GtRefreshToken && client.GetRefreshTTL() <= 0 {
		oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
		return
	} else if grantType == oauth2.GtRefreshToken && client.GetRefreshTTL() > 0 {
		// https://datatracker.ietf.org/doc/html/rfc6749#section-6
		refreshTokenForm := r.PostFormValue(oauth2.ParameterRefreshToken)
		refreshToken, refreshTokenExists := handler.tokenManager.GetRefreshToken(refreshTokenForm)
		if !refreshTokenExists {
			oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}

		if refreshToken.ClientId != client.Id {
			oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtInvalidRequest})
			return
		}

		username = refreshToken.Username
		scopes = refreshToken.Scopes
	} else {
		oauth2.TokenErrorResponseHandler(w, &oauth2.TokenErrorResponseParameter{Error: oauth2.TokenEtUnsupportedGrandType})
		return
	}

	accessTokenResponse := handler.tokenManager.CreateAccessTokenResponse(username, client, scopes)

	jsonError := internalHttp.SendJson(accessTokenResponse, w)
	if jsonError != nil {
		serverHandler.InternalServerErrorHandler(w, r)
		return
	}
}
