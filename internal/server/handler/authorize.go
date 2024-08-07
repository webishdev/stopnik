package handler

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"regexp"
	"stopnik/internal/config"
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
			log.Error("Invalid client id %s", clientId)
			BadRequestHandler(w, r)
			return
		}

		redirect := r.URL.Query().Get(oauth2.ParameterRedirectUri)

		redirectURL, urlParseError := url.Parse(redirect)
		if urlParseError != nil {
			log.Error("Could not parse redirect URI %s for client %s", redirect, client.Id)
			BadRequestHandler(w, r)
			return
		}

		invalidRedirectErrorHandler := validateRedirect(client, redirect)
		if invalidRedirectErrorHandler != nil {
			invalidRedirectErrorHandler(w, r)
			return
		}

		state := r.URL.Query().Get(oauth2.ParameterState)

		responseTypeQueryParameter := r.URL.Query().Get(oauth2.ParameterResponseType)
		responseType, valid := oauth2.ResponseTypeFromString(responseTypeQueryParameter)
		if !valid {
			log.Error("Invalid %s parameter with value %s for client %s", oauth2.ParameterResponseType, responseTypeQueryParameter, client.Id)

			errorMessage := fmt.Sprintf("Invalid %s parameter value", oauth2.ParameterResponseType)
			authorizeError := &oauth2.ErrorResponseParameter{Error: oauth2.EtInvalidRequest, Description: errorMessage}
			oauth2.ErrorResponseHandler(w, redirectURL, state, authorizeError)
			return
		}

		scope := r.URL.Query().Get(oauth2.ParameterScope)

		codeChallenge := ""
		codeChallengeMethod := ""
		if responseType == oauth2.RtCode {
			codeChallenge = r.URL.Query().Get(pkce.ParameterCodeChallenge)
			codeChallengeMethod = r.URL.Query().Get(pkce.ParameterCodeChallengeMethod)
		}

		if log.IsDebug() {
			log.Debug("Response type: %s", responseType)
			log.Debug("Redirect URI: %s", redirect)
			log.Debug("State: %s", state)
			log.Debug("Scope: %s", scope)
		}

		scopes := strings.Split(scope, " ")

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

			query := redirectURL.Query()

			if responseType == oauth2.RtToken {
				accessTokenResponse := handler.tokenManager.CreateAccessTokenResponse(user.Username, client, scopes)
				query.Set(oauth2.ParameterAccessToken, accessTokenResponse.AccessTokenKey)
				query.Set(oauth2.ParameterTokenType, string(accessTokenResponse.TokenType))
				query.Set(oauth2.ParameterExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			} else if responseType == oauth2.RtCode {
				query.Set(oauth2.ParameterCode, id.String())
			} else {
				log.Error("Invalid response type %s", responseType)
				oauth2.ErrorResponseHandler(w, redirectURL, state, &oauth2.ErrorResponseParameter{Error: oauth2.EtUnsupportedResponseType})
				return
			}

			if state != "" {
				query.Set(oauth2.ParameterState, state)
			}

			redirectURL.RawQuery = query.Encode()

			w.Header().Set(internalHttp.Location, redirectURL.String())
			w.WriteHeader(http.StatusFound)
		} else {
			// http.ServeFile(w, r, "foo.html")
			// bytes := []byte(loginHtml)

			// Show login page
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
			query.Set(oauth2.ParameterAccessToken, accessTokenResponse.AccessTokenKey)
			query.Set(oauth2.ParameterTokenType, string(accessTokenResponse.TokenType))
			query.Set(oauth2.ParameterExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
			// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
			// The authorization server MUST NOT issue a refresh token.
		} else {
			query.Set(oauth2.ParameterCode, authSessionForm)
		}

		if authSession.State != "" {
			query.Set(oauth2.ParameterState, authSession.State)
		}

		redirectURL.RawQuery = query.Encode()

		w.Header().Set(internalHttp.Location, redirectURL.String())
		w.WriteHeader(http.StatusFound)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}

func validateRedirect(client *config.Client, redirect string) func(w http.ResponseWriter, r *http.Request) {
	if redirect == "" {
		log.Error("Redirect provided for client %s was empty", client.Id)
		return BadRequestHandler
	}
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
				log.Error("Cloud not match redirect URI %s for client %s", redirect, client.Id)
				return InternalServerErrorHandler
			}

			matchesRedirect = matchesRedirect || matched
		}

		if !matchesRedirect {
			log.Error("Configuration for client %s does not match the given redirect URI %s", client.Id, redirect)
			return BadRequestHandler
		}
	} else {
		log.Error("Client %s has no redirect URI(s) configured!", client.Id)
		return BadRequestHandler
	}

	return nil
}
