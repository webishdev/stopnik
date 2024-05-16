package handler

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"regexp"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/internal/pkce"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"stopnik/internal/template"
	"stopnik/log"
	"strings"
)

type AuthorizeHandler struct {
	validator      *validation.RequestValidator
	cookieManager  *internalHttp.CookieManager
	sessionManager *store.SessionManager
	tokenManager   *store.TokenManager
}

func CreateAuthorizeHandler(validator *validation.RequestValidator, cookieManager *internalHttp.CookieManager, sessionManager *store.SessionManager, tokenManager *store.TokenManager) *AuthorizeHandler {
	return &AuthorizeHandler{
		validator:      validator,
		cookieManager:  cookieManager,
		sessionManager: sessionManager,
		tokenManager:   tokenManager,
	}
}

func (handler *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		clientId := r.URL.Query().Get(oauth2.ParameterClientId)
		client, exists := handler.validator.ValidateClientId(clientId)
		if !exists {
			ForbiddenHandler(w, r)
			return
		}

		responseTypeQueryParameter := r.URL.Query().Get(oauth2.ParameterResponseType)
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			ForbiddenHandler(w, r)
			return
		}

		redirect := r.URL.Query().Get(oauth2.ParameterRedirectUri)
		state := r.URL.Query().Get(oauth2.ParameterState)
		scope := r.URL.Query().Get(oauth2.ParameterScope)
		codeChallenge := r.URL.Query().Get(pkce.ParameterCodeChallenge)
		codeChallengeMethod := r.URL.Query().Get(pkce.ParameterCodeChallengeMethod)

		log.Debug("Response type: %s", responseType)
		log.Debug("Redirect URI: %s", redirect)
		log.Debug("State: %s", state)
		log.Debug("Scope: %s", scope)

		scopes := strings.Split(scope, " ")

		redirectCount := len(client.Redirects)

		if redirectCount > 0 {
			matchesRedirect := false
			for redirectIndex := range redirectCount {
				clientRedirect := client.Redirects[redirectIndex]
				endsWithWildcard := strings.HasSuffix(clientRedirect, "*")
				if endsWithWildcard {
					clientRedirect = strings.Replace(clientRedirect, "*", ".*", 1)
				}
				clientRedirect = fmt.Sprintf("^%s$", clientRedirect)
				matched, regexError := regexp.MatchString(clientRedirect, redirect)
				if regexError != nil {
					InternalServerErrorHandler(w, r)
					return
				}

				matchesRedirect = matchesRedirect || matched
			}

			if !matchesRedirect {
				ForbiddenHandler(w, r)
				return
			}
		} else {
			log.Error("Client %s has no redirect URI(s) configured!", client.Id)
			ForbiddenHandler(w, r)
			return
		}

		id := uuid.New()
		authSession := &store.AuthSession{
			Id:                  id.String(),
			Redirect:            redirect,
			AuthURI:             r.URL.RequestURI(),
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ClientId:            clientId,
			ResponseType:        string(responseType),
			Scopes:              scopes,
			State:               state,
		}

		handler.sessionManager.StartSession(authSession)

		user, validCookie := handler.cookieManager.ValidateCookie(r)

		if validCookie {
			authSession.Username = user.Username
			redirectURL, urlParseError := url.Parse(redirect)
			if urlParseError != nil {
				InternalServerErrorHandler(w, r)
				return
			}

			query := redirectURL.Query()

			if responseType == oauth2.RtToken {
				accessTokenResponse := handler.tokenManager.CreateAccessTokenResponse(user.Username, client, scopes)
				query.Add(oauth2.ParameterAccessToken, accessTokenResponse.AccessTokenKey)
				query.Add(oauth2.ParameterTokenType, string(accessTokenResponse.TokenType))
				query.Add(oauth2.ParameterExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			} else {
				query.Add(oauth2.ParameterCode, id.String())
			}

			if state != "" {
				query.Add(oauth2.ParameterState, state)
			}

			redirectURL.RawQuery = query.Encode()

			w.Header().Set(internalHttp.Location, redirectURL.String())
			w.WriteHeader(http.StatusFound)
		} else {
			// http.ServeFile(w, r, "foo.html")
			// bytes := []byte(loginHtml)
			query := r.URL.Query()
			encodedQuery := query.Encode()
			formAction := fmt.Sprintf("authorize?%s", encodedQuery)
			loginTemplate := template.LoginTemplate(authSession.Id, formAction)

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		}
	} else if r.Method == http.MethodPost {
		// Handle Post from Login
		user, userExists := handler.validator.ValidateFormLogin(r)
		if !userExists {
			w.Header().Set(internalHttp.Location, r.RequestURI)
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		cookie, err := handler.cookieManager.CreateCookie(user.Username)
		if err != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		http.SetCookie(w, &cookie)

		authSessionForm := r.PostFormValue("stopnik_auth_session")
		authSession, exists := handler.sessionManager.GetSession(authSessionForm)
		if !exists {
			w.Header().Set(internalHttp.Location, r.RequestURI)
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		authSession.Username = user.Username
		redirectURL, urlParseError := url.Parse(authSession.Redirect)
		if urlParseError != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		query := redirectURL.Query()
		if authSession.ResponseType == string(oauth2.RtToken) {
			client, exists := handler.validator.ValidateClientId(authSession.ClientId)
			if !exists {
				InternalServerErrorHandler(w, r)
				return
			}
			accessTokenResponse := handler.tokenManager.CreateAccessTokenResponse(user.Username, client, authSession.Scopes)
			query.Add(oauth2.ParameterAccessToken, accessTokenResponse.AccessTokenKey)
			query.Add(oauth2.ParameterTokenType, string(accessTokenResponse.TokenType))
			query.Add(oauth2.ParameterExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
			// The authorization server MUST NOT issue a refresh token.
		} else {
			query.Add(oauth2.ParameterCode, authSessionForm)
		}

		if authSession.State != "" {
			query.Add(oauth2.ParameterState, authSession.State)
		}

		redirectURL.RawQuery = query.Encode()

		w.Header().Set(internalHttp.Location, redirectURL.String())
		w.WriteHeader(http.StatusFound)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
