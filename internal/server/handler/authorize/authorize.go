package authorize

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
)

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
		user, loginError := h.validator.ValidateFormLogin(r)
		if loginError != nil {
			h.sendRetryLocation(w, r, *loginError)
			return
		}

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
		authSession.AuthTime = loginSession.StartTime
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
			accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, user.Username, client, &loginSession.StartTime, authSession.Scopes, authSession.Nonce, "")
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
		invalidRedirectErrorHandler(w, r)
		return
	}

	responseTypes, validResponseTypes := h.getResponseTypes(authorizeRequest.responseTypeParameter)
	if !validResponseTypes {
		log.Error("Invalid %s parameter with value %s for client %s", oauth2.ParameterResponseType, authorizeRequest.responseTypeParameter, client.Id)

		errorMessage := fmt.Sprintf("Invalid %s parameter value", oauth2.ParameterResponseType)
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizeError)
		return
	}

	if !slices.Contains(responseTypes, oauth2.RtCode) && authorizeRequest.codeChallengeParameter != "" && authorizeRequest.codeChallengeMethodParameter != "" {
		errorMessage := fmt.Sprintf("Code challenge should only be used for response type %s", oauth2.RtCode)
		authorizeError := &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest, Description: errorMessage}
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizeError)
		return
	}

	if log.IsDebug() {
		log.Debug("Response types: %v", responseTypes)
		log.Debug("Redirect URI: %s", authorizeRequest.redirectParameter)
		log.Debug("State: %s", authorizeRequest.stateParameter)
		log.Debug("Scope: %v", authorizeRequest.requestedScopes)
	}

	id := uuid.NewString()
	authSession := &session.AuthSession{
		Id:                  id,
		Redirect:            authorizeRequest.redirectParameter,
		AuthURI:             r.URL.RequestURI(),
		CodeChallenge:       authorizeRequest.codeChallengeParameter,
		CodeChallengeMethod: authorizeRequest.codeChallengeMethodParameter,
		ClientId:            authorizeRequest.clientIdParameter,
		ResponseTypes:       responseTypes,
		Scopes:              authorizeRequest.requestedScopes,
		State:               authorizeRequest.stateParameter,
	}

	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authorizeRequest.nonceParameter != "" {
		authSession.Nonce = authorizeRequest.nonceParameter
	} else if authorizeRequest.nonceParameter != "" {
		log.Error("Nonce used without OpenID Connect setting for client with id %s", client.Id)
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		return
	}

	idTokenRequest := slices.Contains(responseTypes, oauth2.RtIdToken) && len(responseTypes) == 1

	if !idTokenRequest {
		h.authSessionManager.StartSession(authSession)
	}

	user, loginSession, validCookie := h.cookieManager.ValidateAuthCookie(r)

	var promptType *oidc.PromptType
	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authorizeRequest.promptParameter != "" {
		var authorizationErrorResponse *oauth2.AuthorizationErrorResponseParameter
		promptType, authorizationErrorResponse = h.getPromptType(validCookie, authorizeRequest.promptParameter)
		if authorizationErrorResponse != nil {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizationErrorResponse)
			return
		}
	} else if authorizeRequest.promptParameter != "" {
		log.Error("Prompt used without OpenID Connect setting for client with id %s", client.Id)
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		return
	}

	var maxAge *int
	if client.Oidc && oidc.HasOidcScope(authorizeRequest.requestedScopes) && authorizeRequest.maxAgeParameter != "" {
		maxAgeResult, maxAgeError := strconv.Atoi(authorizeRequest.maxAgeParameter)
		if maxAgeError != nil {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
			return
		}
		maxAge = &maxAgeResult
	} else if authorizeRequest.maxAgeParameter != "" {
		log.Error("Max age used without OpenID Connect setting for client with id %s", client.Id)
		oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, &oauth2.AuthorizationErrorResponseParameter{Error: oauth2.AuthorizationEtInvalidRequest})
		return
	}

	if validCookie && !h.forceLogin(loginSession, promptType, maxAge) {
		authSession.Username = user.Username
		authSession.AuthTime = loginSession.StartTime

		query, authorizationErrorResponse := h.createLocationResponseQuery(r, redirectURL, user, client, authorizeRequest.requestedScopes, authSession, loginSession, responseTypes, id, idTokenRequest, authorizeRequest.stateParameter)
		if authorizationErrorResponse != nil {
			oauth2.AuthorizationErrorResponseHandler(w, redirectURL, authorizeRequest.stateParameter, authorizationErrorResponse)
			return
		}

		sendFound(w, redirectURL, query)
	} else {
		// Show login page
		h.sendLogin(w, r, authSession.Id)
	}
}

func (h *Handler) validateRedirect(client *config.Client, redirect string) func(w http.ResponseWriter, r *http.Request) {
	if redirect == "" {
		log.Error("Redirect provided for client %s was empty", client.Id)
		return func(w http.ResponseWriter, r *http.Request) {
			h.sendErrorPage(w, r, "No redirect provided")
		}
	}

	validRedirect := client.ValidateRedirect(redirect)
	if !validRedirect {
		log.Error("Invalid redirect to %s for client %s", redirect, client.Id)
		message := fmt.Sprintf("Invalid redirect: %s", redirect)
		return func(w http.ResponseWriter, r *http.Request) {
			h.sendErrorPage(w, r, message)
		}
	}

	return nil
}

func (h *Handler) createLocationResponseQuery(r *http.Request, redirectURL *url.URL, user *config.User, client *config.Client, scopes []string, authSession *session.AuthSession, loginSession *session.LoginSession, responseTypes []oauth2.ResponseType, id string, idTokenRequest bool, stateParameter string) (url.Values, *oauth2.AuthorizationErrorResponseParameter) {
	query := redirectURL.Query()

	var idToken string
	accessTokenResponse := h.tokenManager.CreateAccessTokenResponse(r, user.Username, client, &loginSession.StartTime, scopes, authSession.Nonce, "")
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

func sendFound(w http.ResponseWriter, redirectURL *url.URL, query url.Values) {
	redirectURL.RawQuery = query.Encode()

	w.Header().Set(internalHttp.Location, redirectURL.String())
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

	if h.config.GetOidc() && oidc.HasOidcScope(scopes) && requestParameter != "" {
		parsedRequestToken, requestParameterParseError := jwt.Parse([]byte(requestParameter), jwt.WithVerify(true))
		if requestParameterParseError == nil {
			// OAuth2
			clientIdParameter = getClaimFromToken(parsedRequestToken, oauth2.ParameterClientId, clientIdParameter)
			stateParameter = getClaimFromToken(parsedRequestToken, oauth2.ParameterState, stateParameter)
			responseTypeParameter = getClaimFromToken(parsedRequestToken, oauth2.ParameterResponseType, responseTypeParameter)
			redirectParameter = getClaimFromToken(parsedRequestToken, oauth2.ParameterRedirectUri, redirectParameter)
			scopeParameter = getClaimFromToken(parsedRequestToken, oauth2.ParameterScope, scopeParameter)

			// PKCE
			codeChallengeParameter = getClaimFromToken(parsedRequestToken, pkce.ParameterCodeChallenge, codeChallengeParameter)
			codeChallengeMethodParameter = getClaimFromToken(parsedRequestToken, pkce.ParameterCodeChallengeMethod, codeChallengeMethodParameter)

			// OpenId Connect
			nonceParameter = getClaimFromToken(parsedRequestToken, oidc.ParameterNonce, nonceParameter)
			promptParameter = getClaimFromToken(parsedRequestToken, oidc.ParameterPrompt, promptParameter)
			maxAgeParameter = getClaimFromToken(parsedRequestToken, oidc.ParameterMaxAge, maxAgeParameter)

			requestedClaimsValue, requestedClaimsValueExists := parsedRequestToken.Get(oidc.ParameterClaims)
			if requestedClaimsValueExists {
				parameter, ok := requestedClaimsValue.(oidc.ClaimsParameter)
				if ok {
					requestedClaims = &parameter
				} else {
					log.Error("Could not extract claims from request object")
				}
			}
		}
	}

	scopes = strings.Split(scopeParameter, " ")

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
		requestedScopes:              scopes,
		requestedClaims:              requestedClaims,
	}
}

func getClaimFromToken(token jwt.Token, claim string, defaultValue string) string {
	value, exists := token.Get(claim)
	if exists {
		valueAsString := fmt.Sprintf("%s", value)
		if valueAsString != "" {
			return valueAsString
		}
	}
	return defaultValue
}
