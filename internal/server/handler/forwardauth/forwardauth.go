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

type Handler struct {
	config                *config.Config
	cookieManager         *cookie.Manager
	authSessionManager    session.Manager[session.AuthSession]
	forwardSessionManager session.Manager[session.ForwardSession]
	templateManager       *template.Manager
	errorHandler          *internalError.Handler
}

func NewForwardAuthHandler(cookieManager *cookie.Manager, authSessionManager session.Manager[session.AuthSession], forwardSessionManager session.Manager[session.ForwardSession], templateManager *template.Manager) *Handler {
	currentConfig := config.GetConfigInstance()
	return &Handler{
		config:                currentConfig,
		cookieManager:         cookieManager,
		authSessionManager:    authSessionManager,
		forwardSessionManager: forwardSessionManager,
		templateManager:       templateManager,
		errorHandler:          internalError.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)

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
		h.errorHandler.InternalServerErrorHandler(w, r)
		return
	}

	forwardAuthParameterName := h.config.GetForwardAuthParameterName()

	codeParameter := forwardUri.Query().Get(oauth2.ParameterCode)
	forwardIdParameter := forwardUri.Query().Get(forwardAuthParameterName)

	_, validCookie := h.cookieManager.ValidateAuthCookie(r)

	if validCookie {
		w.WriteHeader(http.StatusOK)
		return
	}

	if codeParameter != "" && forwardIdParameter != "" {
		authCookie, forwardSession, valid := h.validate(codeParameter, forwardIdParameter)
		if !valid {
			h.errorHandler.InternalServerErrorHandler(w, r)
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

	redirectUri, redirectUriError := createUri(forwardString, "", func(query url.Values) {
		query.Set(forwardAuthParameterName, forwardSessionId)
	})
	if redirectUriError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r)
		return
	}

	log.Info("Will redirect to %s", redirectUri.String())

	parsedUri, parsedUriError := createUri(h.config.Server.ForwardAuth.ExternalUrl, endpoint.Authorization, func(query url.Values) {
		query.Set(oauth2.ParameterResponseType, string(oauth2.RtCode))
		query.Set(oauth2.ParameterClientId, "fooobar")
		query.Set(oauth2.ParameterState, "abc")
		query.Set(oauth2.ParameterScope, "xzy")
		query.Set(oauth2.ParameterRedirectUri, redirectUri.String())
		query.Set(pkce.ParameterCodeChallengeMethod, string(pkce.S256))
		query.Set(pkce.ParameterCodeChallenge, codeChallenge)
	})
	if parsedUriError != nil {
		h.errorHandler.InternalServerErrorHandler(w, r)
		return
	}
	forwardSession := &session.ForwardSession{
		Id:                    forwardSessionId,
		CodeChallengeVerifier: codeChallengeVerifier,
		RedirectUri:           forwardString,
	}

	h.forwardSessionManager.StartSession(forwardSession)

	w.Header().Set("Location", parsedUri.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func (h *Handler) validate(code string, forwardSessionId string) (*http.Cookie, *session.ForwardSession, bool) {
	authSession, authSessionExists := h.authSessionManager.GetSession(code)
	forwardSession, forwardSessionExists := h.forwardSessionManager.GetSession(forwardSessionId)
	if authSessionExists && forwardSessionExists {
		codeChallengeMethod, codeChallengeMethodExists := pkce.CodeChallengeMethodFromString(authSession.CodeChallengeMethod)
		if codeChallengeMethodExists {
			validatePKCE := pkce.ValidatePKCE(codeChallengeMethod, forwardSession.CodeChallengeVerifier, authSession.CodeChallenge)
			if validatePKCE {
				authCookie, authCookieError := h.cookieManager.CreateAuthCookie(authSession.Username)
				if authCookieError != nil {
					return nil, nil, false
				}

				return &authCookie, forwardSession, true
			}
		}
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
