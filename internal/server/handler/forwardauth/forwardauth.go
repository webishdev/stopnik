package forwardauth

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	internalError "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"net/url"
)

const forwardAuthScope = "forward:auth"

type Handler struct {
	config                *config.Config
	cookieManager         *cookie.Manager
	authSessionManager    session.Manager[session.AuthSession]
	forwardSessionManager session.Manager[session.ForwardSession]
	loginSessionManager   session.Manager[session.LoginSession]
	templateManager       *template.Manager
	errorHandler          *internalError.Handler
}

func NewForwardAuthHandler(cookieManager *cookie.Manager, authSessionManager session.Manager[session.AuthSession], forwardSessionManager session.Manager[session.ForwardSession], loginSessionManager session.Manager[session.LoginSession], templateManager *template.Manager) *Handler {
	currentConfig := config.GetConfigInstance()
	return &Handler{
		config:                currentConfig,
		cookieManager:         cookieManager,
		authSessionManager:    authSessionManager,
		forwardSessionManager: forwardSessionManager,
		loginSessionManager:   loginSessionManager,
		templateManager:       templateManager,
		errorHandler:          internalError.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)

	forwardAuthClient, forwardAuthClientExists := h.config.GetForwardAuthClient()
	if !forwardAuthClientExists {
		h.errorHandler.BadRequestHandler(w, r)
		return
	}

	forwardProtocol := r.Header.Get(internalHttp.XForwardProtocol)
	forwardHost := r.Header.Get(internalHttp.XForwardHost)
	forwardPath := r.Header.Get(internalHttp.XForwardUri)

	if forwardProtocol == "" || forwardHost == "" || forwardPath == "" {
		h.errorHandler.BadRequestHandler(w, r)
		return
	}

	forwardString := fmt.Sprintf("%s://%s%s", forwardProtocol, forwardHost, forwardPath)
	forwardUri, forwardUriError := url.Parse(forwardString)
	if forwardUriError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, forwardUriError)
		return
	}

	forwardAuthParameterName := h.config.GetForwardAuthParameterName()

	codeParameter := forwardUri.Query().Get(oauth2.ParameterCode)
	stateParameter := forwardUri.Query().Get(oauth2.ParameterState)
	forwardIdParameter := forwardUri.Query().Get(forwardAuthParameterName)

	_, _, validCookie := h.cookieManager.ValidateForwardAuthCookie(r)

	if validCookie && codeParameter == "" && forwardIdParameter == "" && stateParameter == "" {
		w.WriteHeader(http.StatusOK)
		return
	} else if validCookie && codeParameter != "" && forwardIdParameter != "" && stateParameter != "" {
		_, forwardSession, valid := h.validatePKCEAndState(codeParameter, stateParameter, forwardIdParameter)
		if !valid {
			h.errorHandler.BadRequestHandler(w, r)
			return
		} else {
			w.Header().Set(internalHttp.Location, forwardSession.RedirectUri)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
	}

	if codeParameter != "" && forwardIdParameter != "" && stateParameter != "" {
		authCookie, forwardSession, valid := h.validateAndCreateAuthCookie(codeParameter, stateParameter, forwardIdParameter)
		if !valid {
			h.errorHandler.BadRequestHandler(w, r)
			return
		} else {
			http.SetCookie(w, authCookie)
			w.Header().Set(internalHttp.Location, forwardSession.RedirectUri)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
	}

	codeChallenge := uuid.NewString()
	codeChallengeVerifier := pkce.CalculatePKCE(pkce.S256, codeChallenge)
	forwardSessionId := uuid.NewString()
	forwardSessionState := uuid.NewString()

	redirectUri, redirectUriError := createUri(forwardString, "", func(query url.Values) {
		query.Set(forwardAuthParameterName, forwardSessionId)
	})
	if redirectUriError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, redirectUriError)
		return
	}

	log.Info("Will redirect to %s", redirectUri.String())

	parsedUri, parsedUriError := createUri(h.config.Server.ForwardAuth.ExternalUrl, endpoint.Authorization, func(query url.Values) {
		query.Set(oauth2.ParameterResponseType, string(oauth2.RtCode))
		query.Set(oauth2.ParameterClientId, forwardAuthClient.Id)
		query.Set(oauth2.ParameterState, forwardSessionState)
		query.Set(oauth2.ParameterScope, forwardAuthScope)
		query.Set(oauth2.ParameterRedirectUri, redirectUri.String())
		query.Set(pkce.ParameterCodeChallengeMethod, string(pkce.S256))
		query.Set(pkce.ParameterCodeChallenge, codeChallenge)
	})
	if parsedUriError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r, parsedUriError)
		return
	}
	forwardSession := &session.ForwardSession{
		Id:                    forwardSessionId,
		CodeChallengeVerifier: codeChallengeVerifier,
		RedirectUri:           forwardString,
		State:                 forwardSessionState,
	}

	h.forwardSessionManager.StartSession(forwardSession)

	w.Header().Set(internalHttp.Location, parsedUri.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func (h *Handler) validatePKCEAndState(code string, state string, forwardSessionId string) (*session.AuthSession, *session.ForwardSession, bool) {
	authSession, authSessionExists := h.authSessionManager.GetSession(code)
	if authSessionExists {
		codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authSession.CodeChallengeMethod)
		forwardSession, forwardSessionExists := h.forwardSessionManager.GetSession(forwardSessionId)
		if codeChallengeMethodExists && forwardSessionExists && forwardSession.State == state {
			validatePKCE := pkce.ValidatePKCE(codeChallengeMethod, forwardSession.CodeChallengeVerifier, authSession.CodeChallenge)
			if validatePKCE {
				return authSession, forwardSession, true
			}
		}
	}
	return nil, nil, false
}

func (h *Handler) validateAndCreateAuthCookie(code string, state string, forwardSessionId string) (*http.Cookie, *session.ForwardSession, bool) {
	authSession, forwardSession, valid := h.validatePKCEAndState(code, state, forwardSessionId)
	if valid {
		loginSession := &session.LoginSession{
			Id:       uuid.NewString(),
			Username: authSession.Username,
		}
		h.loginSessionManager.StartSession(loginSession)
		forwardAuthCookie, forwardAuthCookieError := h.cookieManager.CreateForwardAuthCookie(authSession.Username, loginSession.Id)
		if forwardAuthCookieError != nil {
			return nil, nil, false
		}

		return &forwardAuthCookie, forwardSession, true
	}
	return nil, nil, false
}

func createUri(uri string, path string, handler func(query url.Values)) (*url.URL, error) {
	parsedUri, parseError := url.Parse(uri)
	if parseError != nil {
		return nil, parseError
	}

	parsedUri = parsedUri.JoinPath(path)
	if handler != nil {
		query := parsedUri.Query()
		handler(query)
		parsedUri.RawQuery = query.Encode()
	}

	return parsedUri, nil
}
