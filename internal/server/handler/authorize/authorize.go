package authorize

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"
)

// maxAuthSessions limits the number of open authorization sessions.
var maxAuthSessions = 100000

type authorizeRequestValues struct {
	clientIdParameter            string
	redirectParameter            string
	responseTypeParameter        string
	stateParameter               string
	codeChallengeParameter       string
	codeChallengeMethodParameter string
	nonceParameter               string
	promptParameter              string
	maxAgeParameter              string
	requestParameter             string
	requestedScopes              []string
	requestedClaims              *oidc.ClaimsParameter
}

type Handler struct {
	config              *config.Config
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
	currentConfig := config.GetConfigInstance()
	return &Handler{
		config:              currentConfig,
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
		h.handlePostRequest(w, r)
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func (h *Handler) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	authorizeRequest := h.parseRequest(r)
	h.handleAuthorizeRequest(w, r, authorizeRequest)
}

func (h *Handler) handlePostRequest(w http.ResponseWriter, r *http.Request) {
	authSessionForm := r.PostFormValue("stopnik_auth_session")
	if authSessionForm != "" {
		if !validation.ValidateSameOrigin(r) {
			h.errorHandler.ForbiddenHandler(w, r)
			return
		}
		loginToken, loginTokenError := h.validator.GetLoginToken(authSessionForm)
		if loginTokenError != nil {
			h.errorHandler.BadRequestHandler(w, r)
			return
		}
		authSessionId, authSessionIdExists := loginToken.Subject()
		if !authSessionIdExists {
			h.errorHandler.BadRequestHandler(w, r)
			return
		}
		authSession, authSessionExists := h.authSessionManager.GetSession(authSessionId)
		if !authSessionExists {
			h.sendRetryLocation(w, r, "")
			return
		}

		user, loginError := h.validator.ValidateFormLogin(r)
		if loginError != nil {
			h.sendDifferentRetryLocation(w, r, authSession.AuthURI, *loginError)
			return
		}

		loginSession := &session.LoginSession{
			Id:       uuid.New().String(),
			Username: user.Username,
		}
		h.loginSessionManager.StartSession(loginSession)
		authCookie, authCookieError := h.cookieManager.CreateAuthCookie(user.Username, loginSession.Id)
		if authCookieError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, authCookieError)
			return
		}

		authSession.Username = user.Username
		authSession.AuthTime = loginSession.StartTime
		redirectURL, urlParseError := url.Parse(authSession.Redirect)
		if urlParseError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, urlParseError)
			return
		}

		http.SetCookie(w, &authCookie)

		responseTypes := authSession.ResponseTypes

		query := newResponseParameters(redirectURL, responseTypes)
		if slices.Contains(responseTypes, oauth2.RtToken) {
			client, clientExists := h.validator.ValidateClientId(authSession.ClientId)
			if !clientExists {
				h.errorHandler.BadRequestHandler(w, r)
				return
			}
			accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, user.Username, client, &loginSession.StartTime, authSession.Scopes, authSession.RequestedClaims, authSession.Nonce, "")
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

		sendFound(w, redirectURL, query, useFragment(responseTypes))
	} else {
		authorizeRequest := h.parseRequest(r)
		h.handleAuthorizeRequest(w, r, authorizeRequest)
	}

}

func (h *Handler) handleAuthorizeRequest(w http.ResponseWriter, r *http.Request, authorizeRequest *authorizeRequestValues) {
	if authorizeRequest == nil {
		h.errorHandler.InternalServerErrorHandler(w, r, errors.New("no authorization values provided"))
		return
	}
	client, exists := h.validator.ValidateClientId(authorizeRequest.clientIdParameter)
	if !exists {
		log.Error("Invalid client id %s", authorizeRequest.clientIdParameter)
		h.errorHandler.BadRequestHandler(w, r)
		return
	}

	redirectURL, urlParseError := url.Parse(authorizeRequest.redirectParameter)
	if urlParseError != nil {
		log.Error("Could not parse redirect URI %s for client %s", authorizeRequest.redirectParameter, client.Id)
		h.errorHandler.BadRequestHandler(w, r)
		return
	}

	invalidRedirectErrorHandler := h.validateRedirect(client, authorizeRequest.redirectParameter)
	if invalidRedirectErrorHandler != nil {
		invalidRedirectErrorHandler.ServeHTTP(w, r)
		return
	}

	responseTypes, invalidResponseTypeHandler := h.validResponseTypes(authorizeRequest, client, redirectURL)
	if invalidResponseTypeHandler != nil {
		invalidResponseTypeHandler.ServeHTTP(w, r)
		return
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	// Request objects are not supported, so they must not be silently ignored
	if authorizeRequest.requestParameter != "" {
		log.Error("Request object provided by client %s is not supported", client.Id)
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtRequestNotSupported})
		return
	}

	invalidGrantHandler := h.validateGrantAndScopes(client, responseTypes, authorizeRequest, redirectURL)
	if invalidGrantHandler != nil {
		invalidGrantHandler.ServeHTTP(w, r)
		return
	}

	invalidCodeChallengeHandler := h.validateCodeChallenge(client, responseTypes, authorizeRequest, redirectURL)
	if invalidCodeChallengeHandler != nil {
		invalidCodeChallengeHandler.ServeHTTP(w, r)
		return
	}

	if log.IsDebug() {
		log.Debug("Response types: %v", responseTypes)
		log.Debug("Redirect URI: %s", authorizeRequest.redirectParameter)
		log.Debug("Scope: %v", authorizeRequest.requestedScopes)
	}

	id := uuid.New().String()
	authSession := createAuthSession(id, authorizeRequest, r, responseTypes)

	invalidNonceHandler := h.validateNonce(client, authorizeRequest, authSession, redirectURL)
	if invalidNonceHandler != nil {
		invalidNonceHandler.ServeHTTP(w, r)
		return
	}

	invalidRequestedClaimsHandler := h.validateRequestedClaims(client, authorizeRequest, authSession, redirectURL)
	if invalidRequestedClaimsHandler != nil {
		invalidRequestedClaimsHandler.ServeHTTP(w, r)
		return
	}

	idTokenRequest := slices.Contains(responseTypes, oauth2.RtIdToken) && len(responseTypes) == 1

	if !idTokenRequest {
		// Every authorization request creates a session, limit them to avoid running out of memory
		if h.authSessionManager.SessionCount() >= maxAuthSessions {
			log.Error("Too many open authorization sessions, rejecting authorization request for client %s", client.Id)
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtTemporaryUnavailable})
			return
		}
		h.authSessionManager.StartSession(authSession)
	}

	user, loginSession, validCookie := h.cookieManager.ValidateAuthCookie(r)

	promptType, invalidPromptTypeHandler := h.validatePromptType(client, authorizeRequest, validCookie, redirectURL)
	if invalidPromptTypeHandler != nil {
		invalidPromptTypeHandler.ServeHTTP(w, r)
		return
	}

	maxAge, invalidMaxAgeHandler := h.validateMaxAge(client, authorizeRequest, redirectURL)
	if invalidMaxAgeHandler != nil {
		invalidMaxAgeHandler.ServeHTTP(w, r)
		return
	}

	if validCookie && !h.forceLogin(loginSession, promptType, maxAge) {
		authSession.Username = user.Username
		authSession.AuthTime = loginSession.StartTime

		query, authorizationErrorResponse := h.createLocationResponseQuery(r, redirectURL, user, client, authorizeRequest.requestedScopes, authSession, loginSession, responseTypes, authSession.Id, idTokenRequest, authorizeRequest.stateParameter)
		if authorizationErrorResponse != nil {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizationErrorResponse)
			return
		}

		sendFound(w, redirectURL, query, useFragment(responseTypes))
	} else {
		// Show login page
		h.sendLogin(w, r, authSession.Id)
	}
}

func (h *Handler) validateMaxAge(client *config.Client, authorizeRequest *authorizeRequestValues, redirectURL *url.URL) (*int, http.Handler) {
	var maxAge *int
	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authorizeRequest.maxAgeParameter != "" {
		maxAgeResult, maxAgeError := strconv.Atoi(authorizeRequest.maxAgeParameter)
		if maxAgeError != nil {
			return nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
			})
		}
		maxAge = &maxAgeResult
	} else if authorizeRequest.maxAgeParameter != "" {
		log.Error("Max age used without OpenID Connect setting for client with id %s", client.Id)
		return nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		})
	}
	return maxAge, nil
}

func (h *Handler) validatePromptType(client *config.Client, authorizeRequest *authorizeRequestValues, validCookie bool, redirectURL *url.URL) (*oidc.PromptType, http.Handler) {
	var promptType *oidc.PromptType
	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authorizeRequest.promptParameter != "" {
		var authorizationErrorResponse *oauth2.AuthorizationErrorResponseParameter
		promptType, authorizationErrorResponse = h.getPromptType(validCookie, authorizeRequest.promptParameter)
		if authorizationErrorResponse != nil {
			return nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizationErrorResponse)
			})
		}
	} else if authorizeRequest.promptParameter != "" {
		log.Error("Prompt used without OpenID Connect setting for client with id %s", client.Id)
		return nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		})
	}
	return promptType, nil
}

func (h *Handler) validateRequestedClaims(client *config.Client, authorizeRequest *authorizeRequestValues, authSession *session.AuthSession, redirectURL *url.URL) http.Handler {
	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authSession.RequestedClaims != nil {
		authSession.RequestedClaims = authorizeRequest.requestedClaims
	} else if authSession.RequestedClaims != nil {
		log.Error("Requested claims used without OpenID Connect setting for client with id %s", client.Id)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		})
	}
	return nil
}

func (h *Handler) validateNonce(client *config.Client, authorizeRequest *authorizeRequestValues, authSession *session.AuthSession, redirectURL *url.URL) http.Handler {
	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authorizeRequest.nonceParameter != "" {
		authSession.Nonce = authorizeRequest.nonceParameter
	} else if authorizeRequest.nonceParameter != "" {
		log.Error("Nonce used without OpenID Connect setting for client with id %s", client.Id)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		})
	}
	return nil
}

func (h *Handler) validateCodeChallenge(client *config.Client, responseTypes []oauth2.ResponseType, authorizeRequest *authorizeRequestValues, redirectURL *url.URL) http.Handler {
	isUnexpectedCodeChallenge := !slices.Contains(responseTypes, oauth2.RtCode) && authorizeRequest.codeChallengeParameter != "" && authorizeRequest.codeChallengeMethodParameter != ""
	if isUnexpectedCodeChallenge {
		errorMessage := fmt.Sprintf("Code challenge should only be used for response type %s", oauth2.RtCode)
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizeError)
		})
	}

	// https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
	// Public clients can not authenticate at the token endpoint, PKCE is their only protection against code injection
	isMissingCodeChallenge := slices.Contains(responseTypes, oauth2.RtCode) && client.GetClientType() == oauth2.CtPublic && authorizeRequest.codeChallengeParameter == ""
	if isMissingCodeChallenge {
		log.Error("Missing code challenge for public client %s", client.Id)
		errorMessage := "Code challenge is required for public clients"
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizeError)
		})
	}
	return nil
}

func (h *Handler) validateGrantAndScopes(client *config.Client, responseTypes []oauth2.ResponseType, authorizeRequest *authorizeRequestValues, redirectURL *url.URL) http.Handler {
	grantType := oauth2.GtImplicit
	if slices.Contains(responseTypes, oauth2.RtCode) {
		grantType = oauth2.GtAuthorizationCode
	}
	if !client.IsGrantTypeAllowed(grantType) {
		log.Error("Grant type %s is not allowed for client %s", grantType, client.Id)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtUnauthorizedClient})
		})
	}

	disallowedScopes := h.config.GetDisallowedScopes(client, authorizeRequest.requestedScopes)
	if len(disallowedScopes) > 0 {
		log.Error("Scopes %v are not allowed for client %s", disallowedScopes, client.Id)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidScope})
		})
	}
	return nil
}

func (h *Handler) validResponseTypes(authorizeRequest *authorizeRequestValues, client *config.Client, redirectURL *url.URL) ([]oauth2.ResponseType, http.Handler) {
	responseTypes, validResponseTypes := h.getResponseTypes(authorizeRequest.responseTypeParameter)
	if !validResponseTypes {
		log.Error("Invalid %s parameter with value %s for client %s", oauth2.ParameterResponseType, authorizeRequest.responseTypeParameter, client.Id)
		errorMessage := fmt.Sprintf("Invalid %s parameter value", oauth2.ParameterResponseType)
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		return nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizeError)
		})
	}
	return responseTypes, nil
}

func (h *Handler) validateRedirect(client *config.Client, redirect string) http.Handler {
	if redirect == "" {
		log.Error("Redirect provided for client %s was empty", client.Id)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.sendErrorPage(w, r, "No redirect provided")
		})
	}

	validRedirect := client.ValidateRedirect(redirect)
	if !validRedirect {
		log.Error("Invalid redirect to %s for client %s", redirect, client.Id)
		message := fmt.Sprintf("Invalid redirect: %s", redirect)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.sendErrorPage(w, r, message)
		})
	}

	return nil
}

func (h *Handler) createLocationResponseQuery(r *http.Request, redirectURL *url.URL, user *config.User, client *config.Client, scopes []string, authSession *session.AuthSession, loginSession *session.LoginSession, responseTypes []oauth2.ResponseType, id string, idTokenRequest bool, stateParameter string) (url.Values, *oauth2.AuthorizationErrorResponseParameter) {
	query := newResponseParameters(redirectURL, responseTypes)

	var idToken string
	accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, user.Username, client, &loginSession.StartTime, scopes, authSession.RequestedClaims, authSession.Nonce, "")
	if slices.Contains(responseTypes, oauth2.RtToken) {
		setImplicitGrantParameter(query, accessTokenResponse)
	} else if slices.Contains(responseTypes, oauth2.RtCode) {
		setAuthorizationGrantParameter(query, id)
	} else if idTokenRequest {
		if accessTokenResponse.IdTokenValue == "" {
			system.CriticalError(errors.New("no id_token found in response"))
		}
		idToken = accessTokenResponse.IdTokenValue
	} else {
		log.Error("Invalid response type %v", responseTypes)
		return nil, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtUnsupportedResponseType}
	}

	if stateParameter != "" {
		query.Set(oauth2.ParameterState, stateParameter)
	}

	if idToken != "" {
		setIdTokenParameter(query, idToken)
	}
	return query, nil
}

func (h *Handler) getPromptType(validCookie bool, promptQueryParameter string) (*oidc.PromptType, *oauth2.AuthorizationErrorResponseParameter) {
	promptType, validPromptType := oidc.PromptTypeFromString(promptQueryParameter)
	if !validPromptType {
		errorMessage := fmt.Sprintf("Invalid %s parameter value", oidc.ParameterPrompt)
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		return nil, authorizeError
	}

	if !validCookie && promptType == oidc.PtNone {
		errorMessage := "Requested to skip login for unauthenticated user"
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtLoginRequired, Description: errorMessage}
		return nil, authorizeError
	}

	return &promptType, nil
}

func (h *Handler) forceLogin(loginSession *session.LoginSession, promptType *oidc.PromptType, maxAge *int) bool {
	if loginSession == nil {
		return true
	}
	if promptType != nil {
		switch *promptType {
		case oidc.PtLogin:
			return true
		}
	}
	if maxAge != nil && *maxAge > 0 {
		now := time.Now()
		maxSessionStartTime := loginSession.StartTime.Add(time.Second * time.Duration(*maxAge))
		return now.After(maxSessionStartTime)
	} else if maxAge != nil && *maxAge == 0 {
		return true
	}

	return false
}

func (h *Handler) getResponseTypes(responseTypeQueryParameter string) ([]oauth2.ResponseType, bool) {
	var responseTypes []oauth2.ResponseType
	responseTypeQueryParameters := strings.Split(responseTypeQueryParameter, " ")
	for _, currentQueryParameter := range responseTypeQueryParameters {
		responseType, validResponseType := oauth2.ResponseTypeFromString(currentQueryParameter)
		if !validResponseType {
			return nil, false
		}
		responseTypes = append(responseTypes, responseType)
	}
	return responseTypes, true
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

func (h *Handler) sendLogin(w http.ResponseWriter, r *http.Request, authSessionId string) {
	message := h.cookieManager.GetMessageCookieValue(r)

	formAction := endpoint.Authorization[1:]
	loginToken := h.validator.NewLoginToken(authSessionId)
	loginTemplate := h.templateManager.LoginTemplate(loginToken, formAction, message)

	requestData := internalHttp.NewRequestData(r)
	responseWriter := internalHttp.NewResponseWriter(w, requestData)

	responseWriter.SetEncodingHeader()
	w.Header().Set(internalHttp.ContentType, internalHttp.ContentTypeHTML)

	_, writeError := responseWriter.Write(loginTemplate.Bytes())
	if writeError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, writeError)
		return
	}
}

func (h *Handler) sendErrorPage(w http.ResponseWriter, r *http.Request, message string) {
	errorTemplate := h.templateManager.ErrorTemplate(message)

	requestData := internalHttp.NewRequestData(r)
	responseWriter := internalHttp.NewResponseWriter(w, requestData)

	responseWriter.SetEncodingHeader()
	w.Header().Set(internalHttp.ContentType, internalHttp.ContentTypeHTML)

	_, writeError := responseWriter.Write(errorTemplate.Bytes())
	if writeError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, writeError)
		return
	}
}

func (h *Handler) sendRetryLocation(w http.ResponseWriter, r *http.Request, message string) {
	if message != "" {
		messageCookie := h.cookieManager.CreateMessageCookie("Invalid credentials")
		http.SetCookie(w, &messageCookie)
	}
	w.Header().Set(internalHttp.Location, r.RequestURI)
	w.WriteHeader(http.StatusSeeOther)
}

func (h *Handler) sendDifferentRetryLocation(w http.ResponseWriter, r *http.Request, uri string, message string) {
	if message != "" {
		messageCookie := h.cookieManager.CreateMessageCookie("Invalid credentials")
		http.SetCookie(w, &messageCookie)
	}
	w.Header().Set(internalHttp.Location, uri)
	w.WriteHeader(http.StatusSeeOther)
}

// useFragment returns whether the response parameters must be added as fragment instead of query.
// https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
// Tokens in the fragment are not sent to servers, so they do not end up in server logs or referrer headers.
func useFragment(responseTypes []oauth2.ResponseType) bool {
	return slices.Contains(responseTypes, oauth2.RtToken) || slices.Contains(responseTypes, oauth2.RtIdToken)
}

// newResponseParameters returns the values to which the response parameters will be added,
// for query responses these are the existing query parameters of the redirect URI.
func newResponseParameters(redirectURL *url.URL, responseTypes []oauth2.ResponseType) url.Values {
	if useFragment(responseTypes) {
		return url.Values{}
	}
	return redirectURL.Query()
}

func sendFound(w http.ResponseWriter, redirectURL *url.URL, parameters url.Values, fragment bool) {
	location := *redirectURL
	if fragment {
		location.Fragment = ""
		location.RawFragment = ""
		w.Header().Set(internalHttp.Location, location.String()+"#"+parameters.Encode())
	} else {
		location.RawQuery = parameters.Encode()
		w.Header().Set(internalHttp.Location, location.String())
	}
	w.WriteHeader(http.StatusFound)
}

func (h *Handler) parseRequest(r *http.Request) *authorizeRequestValues {
	var clientIdParameter string
	var stateParameter string
	var responseTypeParameter string
	var redirectParameter string
	var scopeParameter string
	var codeChallengeParameter string
	var codeChallengeMethodParameter string
	var nonceParameter string
	var promptParameter string
	var maxAgeParameter string
	var requestParameter string
	var claimsParameter string
	var requestedClaims *oidc.ClaimsParameter

	if r.Method == http.MethodGet {
		// OAuth2
		clientIdParameter = r.URL.Query().Get(oauth2.ParameterClientId)
		stateParameter = r.URL.Query().Get(oauth2.ParameterState)
		responseTypeParameter = r.URL.Query().Get(oauth2.ParameterResponseType)
		redirectParameter = r.URL.Query().Get(oauth2.ParameterRedirectUri)
		scopeParameter = r.URL.Query().Get(oauth2.ParameterScope)

		// PKCE
		codeChallengeParameter = r.URL.Query().Get(pkce.ParameterCodeChallenge)
		codeChallengeMethodParameter = r.URL.Query().Get(pkce.ParameterCodeChallengeMethod)

		// OpenId Connect
		nonceParameter = r.URL.Query().Get(oidc.ParameterNonce)
		promptParameter = r.URL.Query().Get(oidc.ParameterPrompt)
		maxAgeParameter = r.URL.Query().Get(oidc.ParameterMaxAge)
		claimsParameter = r.URL.Query().Get(oidc.ParameterClaims)

		// https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
		requestParameter = r.URL.Query().Get(oidc.ParameterRequest)
	} else if r.Method == http.MethodPost {
		// OAuth2
		clientIdParameter = r.PostFormValue(oauth2.ParameterClientId)
		stateParameter = r.PostFormValue(oauth2.ParameterState)
		responseTypeParameter = r.PostFormValue(oauth2.ParameterResponseType)
		redirectParameter = r.PostFormValue(oauth2.ParameterRedirectUri)
		scopeParameter = r.PostFormValue(oauth2.ParameterScope)

		// PKCE
		codeChallengeParameter = r.PostFormValue(pkce.ParameterCodeChallenge)
		codeChallengeMethodParameter = r.PostFormValue(pkce.ParameterCodeChallengeMethod)

		// OpenId Connect
		nonceParameter = r.PostFormValue(oidc.ParameterNonce)
		promptParameter = r.PostFormValue(oidc.ParameterPrompt)
		maxAgeParameter = r.PostFormValue(oidc.ParameterMaxAge)
		claimsParameter = r.PostFormValue(oidc.ParameterClaims)

		// https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
		requestParameter = r.PostFormValue(oidc.ParameterRequest)
	}

	scopes := strings.Split(scopeParameter, " ")

	if h.config.GetOidc() && claimsParameter != "" {
		requestedClaims = &oidc.ClaimsParameter{}
		claimsParameterParseError := json.Unmarshal([]byte(claimsParameter), requestedClaims)
		if claimsParameterParseError != nil {
			log.Error("Could not parse claims parameter %v", claimsParameterParseError)
		}
	}

	return &authorizeRequestValues{
		clientIdParameter:            clientIdParameter,
		redirectParameter:            redirectParameter,
		responseTypeParameter:        responseTypeParameter,
		stateParameter:               stateParameter,
		codeChallengeParameter:       codeChallengeParameter,
		codeChallengeMethodParameter: codeChallengeMethodParameter,
		nonceParameter:               nonceParameter,
		promptParameter:              promptParameter,
		maxAgeParameter:              maxAgeParameter,
		requestParameter:             requestParameter,
		requestedScopes:              scopes,
		requestedClaims:              requestedClaims,
	}
}

func createAuthSession(id string, authorizeRequest *authorizeRequestValues, r *http.Request, responseTypes []oauth2.ResponseType) *session.AuthSession {
	return &session.AuthSession{
		Id:                  id,
		Redirect:            authorizeRequest.redirectParameter,
		AuthURI:             r.URL.RequestURI(),
		CodeChallenge:       authorizeRequest.codeChallengeParameter,
		CodeChallengeMethod: authorizeRequest.codeChallengeMethodParameter,
		ClientId:            authorizeRequest.clientIdParameter,
		ResponseTypes:       responseTypes,
		Scopes:              authorizeRequest.requestedScopes,
		State:               authorizeRequest.stateParameter,
		RequestedClaims:     authorizeRequest.requestedClaims,
	}
}
