package authorize

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type Handler struct {
	validator           *validation.RequestValidator
	cookieManager       *cookie.Manager
	authSessionManager  session.Manager[session.AuthSession]
	loginSessionManager session.Manager[session.LoginSession]
	tokenManager        *token.Manager
	templateManager     *template.Manager
	errorHandler        *error.Handler
}

func NewAuthorizeHandler(
	validator *validation.RequestValidator,
	cookieManager *cookie.Manager,
	authSessionManager session.Manager[session.AuthSession],
	loginSessionManager session.Manager[session.LoginSession],
	tokenManager *token.Manager,
	templateManager *template.Manager) *Handler {
	return &Handler{
		validator:           validator,
		cookieManager:       cookieManager,
		authSessionManager:  authSessionManager,
		loginSessionManager: loginSessionManager,
		tokenManager:        tokenManager,
		templateManager:     templateManager,
		errorHandler:        error.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		h.handleGetRequest(w, r)
	} else if r.Method == http.MethodPost {
		user, failed := h.validateLogin(w, r)
		if failed {
			return
		}

		h.handlePostRequest(w, r, user)
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (h *Handler) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	clientId := r.URL.Query().Get(oauth2.ParameterClientId)
	client, exists := h.validator.ValidateClientId(clientId)
	if !exists {
		log.Error("Invalid client id %s", clientId)
		h.errorHandler.BadRequestHandler(w, r)
		return
	}

	redirect := r.URL.Query().Get(oauth2.ParameterRedirectUri)

	redirectURL, urlParseError := url.Parse(redirect)
	if urlParseError != nil {
		log.Error("Could not parse redirect URI %s for client %s", redirect, client.Id)
		h.errorHandler.BadRequestHandler(w, r)
		return
	}

	invalidRedirectErrorHandler := h.validateRedirect(client, redirect)
	if invalidRedirectErrorHandler != nil {
		invalidRedirectErrorHandler(w, r)
		return
	}

	state := r.URL.Query().Get(oauth2.ParameterState)

	var responseTypes []oauth2.ResponseType
	responseTypeQueryParameter := r.URL.Query().Get(oauth2.ParameterResponseType)
	responseTypeQueryParameters := strings.Split(responseTypeQueryParameter, " ")
	for _, currentQueryParameter := range responseTypeQueryParameters {
		responseType, valid := oauth2.ResponseTypeFromString(currentQueryParameter)
		if !valid {
			log.Error("Invalid %s parameter with value %s for client %s", oauth2.ParameterResponseType, responseTypeQueryParameter, client.Id)

			errorMessage := fmt.Sprintf("Invalid %s parameter value", oauth2.ParameterResponseType)
			authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, state, authorizeError)
			return
		}
		responseTypes = append(responseTypes, responseType)
	}

	scope := r.URL.Query().Get(oauth2.ParameterScope)

	codeChallenge := r.URL.Query().Get(pkce.ParameterCodeChallenge)
	codeChallengeMethod := r.URL.Query().Get(pkce.ParameterCodeChallengeMethod)

	if !slices.Contains(responseTypes, oauth2.RtCode) && codeChallenge != "" && codeChallengeMethod != "" {
		errorMessage := fmt.Sprintf("Code challenge should only be used for response type %s", oauth2.RtCode)
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, state, authorizeError)
		return
	}

	if log.IsDebug() {
		log.Debug("Response types: %v", responseTypes)
		log.Debug("Redirect URI: %s", redirect)
		log.Debug("State: %s", state)
		log.Debug("Scope: %s", scope)
	}

	scopes := strings.Split(scope, " ")

	id := uuid.NewString()
	authSession := &session.AuthSession{
		Id:                  id,
		Redirect:            redirect,
		AuthURI:             r.URL.RequestURI(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ClientId:            clientId,
		ResponseTypes:       responseTypes,
		Scopes:              scopes,
		State:               state,
	}

	if client.Oidc && oidc.HasOidcScope(scopes) {
		nonceQueryParameter := r.URL.Query().Get(oidc.ParameterNonce)
		authSession.Nonce = nonceQueryParameter
	} else {
		nonceQueryParameter := r.URL.Query().Get(oidc.ParameterNonce)
		if nonceQueryParameter != "" {
			log.Error("Nonce used without OpenID Connect setting for client with id %s", client.Id)
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, state, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})

		}
	}

	idTokenRequest := slices.Contains(responseTypes, oauth2.RtIdToken) && len(responseTypes) == 1

	if !idTokenRequest {
		h.authSessionManager.StartSession(authSession)
	}

	user, _, validCookie := h.cookieManager.ValidateAuthCookie(r)

	if validCookie {
		authSession.Username = user.Username

		query := redirectURL.Query()

		var idToken string
		accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, user.Username, client, scopes, authSession.Nonce)
		if slices.Contains(responseTypes, oauth2.RtToken) {
			setImplicitGrantParameter(query, accessTokenResponse)
		} else if slices.Contains(responseTypes, oauth2.RtCode) {
			setAuthorizationGrantParameter(query, id)
		} else if idTokenRequest {
			accessTokenHash := h.tokenManager.CreateAccessTokenHash(client, accessTokenResponse.AccessTokenValue)
			idToken = h.tokenManager.CreateIdToken(r, user.Username, client, scopes, authSession.Nonce, accessTokenHash)
		} else {
			log.Error("Invalid response type %v", responseTypes)
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, state, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtUnsupportedResponseType})
			return
		}

		if state != "" {
			query.Set(oauth2.ParameterState, state)
		}

		if idToken != "" {
			setIdTokenParameter(query, idToken)
		}

		sendFound(w, redirectURL, query)
	} else {
		// http.ServeFile(w, r, "foo.html")
		// bytes := []byte(loginHtml)

		// Show login page

		message := h.cookieManager.GetMessageCookieValue(r)

		query := r.URL.Query()
		encodedQuery := query.Encode()
		formAction := fmt.Sprintf("authorize?%s", encodedQuery)
		loginToken := h.validator.NewLoginToken(authSession.Id)
		loginTemplate := h.templateManager.LoginTemplate(loginToken, formAction, message)

		requestData := internalHttp.NewRequestData(r)
		responseWriter := internalHttp.NewResponseWriter(w, requestData)

		responseWriter.SetEncodingHeader()

		_, writeError := responseWriter.Write(loginTemplate.Bytes())
		if writeError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, writeError)
			return
		}
	}
}

func (h *Handler) handlePostRequest(w http.ResponseWriter, r *http.Request, user *config.User) {
	loginSession := &session.LoginSession{
		Id:       uuid.NewString(),
		Username: user.Username,
	}
	h.loginSessionManager.StartSession(loginSession)
	authCookie, authCookieError := h.cookieManager.CreateAuthCookie(user.Username, loginSession.Id)
	if authCookieError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, authCookieError)
		return
	}

	authSessionForm := r.PostFormValue("stopnik_auth_session")
	loginToken, loginTokenError := h.validator.GetLoginToken(authSessionForm)
	if loginTokenError != nil {
		h.errorHandler.BadRequestHandler(w, r)
		return
	}
	authSessionId := loginToken.Subject()
	authSession, authSessionExists := h.authSessionManager.GetSession(authSessionId)
	if !authSessionExists {
		h.sendRetryLocation(w, r, "")
		return
	}

	authSession.Username = user.Username
	redirectURL, urlParseError := url.Parse(authSession.Redirect)
	if urlParseError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, urlParseError)
		return
	}

	http.SetCookie(w, &authCookie)

	responseTypes := authSession.ResponseTypes

	query := redirectURL.Query()
	if slices.Contains(responseTypes, oauth2.RtToken) {
		client, clientExists := h.validator.ValidateClientId(authSession.ClientId)
		if !clientExists {
			h.errorHandler.BadRequestHandler(w, r)
			return
		}
		accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, user.Username, client, authSession.Scopes, authSession.Nonce)
		setImplicitGrantParameter(query, accessTokenResponse)
	} else if slices.Contains(responseTypes, oauth2.RtCode) {
		setAuthorizationGrantParameter(query, authSession.Id)
	} else {
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authSession.State, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtUnsupportedResponseType})
		return
	}

	if authSession.State != "" {
		query.Set(oauth2.ParameterState, authSession.State)
	}

	sendFound(w, redirectURL, query)
}

func (h *Handler) validateLogin(w http.ResponseWriter, r *http.Request) (*config.User, bool) {
	// Handle Post from Login
	user, loginError := h.validator.ValidateFormLogin(r)
	if loginError != nil {
		h.sendRetryLocation(w, r, *loginError)
		return nil, true
	}
	return user, false
}

func (h *Handler) validateRedirect(client *config.Client, redirect string) func(w http.ResponseWriter, r *http.Request) {
	validRedirect := client.ValidateRedirect(redirect)

	if !validRedirect {
		return h.errorHandler.BadRequestHandler
	}
	if redirect == "" {
		log.Error("Redirect provided for client %s was empty", client.Id)

	}

	return nil
}

func setAuthorizationGrantParameter(query url.Values, code string) {
	query.Set(oauth2.ParameterCode, code)
}

func setImplicitGrantParameter(query url.Values, accessTokenResponse oauth2.AccessTokenResponse) {
	query.Set(oauth2.ParameterAccessToken, accessTokenResponse.AccessTokenValue)
	query.Set(oauth2.ParameterTokenType, string(accessTokenResponse.TokenType))
	query.Set(oauth2.ParameterExpiresIn, fmt.Sprintf("%d", accessTokenResponse.ExpiresIn))
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
	// The authorization server MUST NOT issue a refresh token.
}

func setIdTokenParameter(query url.Values, idToken string) {
	query.Set(oidc.ParameterIdToken, idToken)
}

func (h *Handler) sendRetryLocation(w http.ResponseWriter, r *http.Request, message string) {
	if message != "" {
		messageCookie := h.cookieManager.CreateMessageCookie("Invalid credentials")
		http.SetCookie(w, &messageCookie)
	}
	w.Header().Set(internalHttp.Location, r.RequestURI)
	w.WriteHeader(http.StatusSeeOther)
}

func sendFound(w http.ResponseWriter, redirectURL *url.URL, query url.Values) {
	redirectURL.RawQuery = query.Encode()

	w.Header().Set(internalHttp.Location, redirectURL.String())
	w.WriteHeader(http.StatusFound)
}
