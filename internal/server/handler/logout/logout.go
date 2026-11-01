package logout

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"net/url"
	"strings"
)

type Handler struct {
	logoutRedirect      string
	cookieManager       *cookie.Manager
	loginSessionManager session.LoginManager[session.LoginSession]
	errorHandler        *error.Handler
}

func NewLogoutHandler(cookieManager *cookie.Manager, loginSessionManager session.LoginManager[session.LoginSession], logoutRedirect string) *Handler {
	return &Handler{
		cookieManager:       cookieManager,
		loginSessionManager: loginSessionManager,
		logoutRedirect:      logoutRedirect,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		if !validation.ValidateSameOrigin(r) {
			h.errorHandler.ForbiddenHandler(w, r)
			return
		}
		_, loginSession, validCookie := h.cookieManager.ValidateAuthCookie(r)
		if !validCookie {
			h.errorHandler.ForbiddenHandler(w, r)
			return
		}
		h.loginSessionManager.CloseSession(loginSession.Id, true)
		authCookie := h.cookieManager.DeleteAuthCookie()

		http.SetCookie(w, &authCookie)

		logoutRedirectFrom := r.PostFormValue("stopnik_logout_redirect")

		if logoutRedirectFrom != "" && isLocalRedirect(logoutRedirectFrom) {
			w.Header().Set(internalHttp.Location, logoutRedirectFrom)
		} else if h.logoutRedirect != "" {
			w.Header().Set(internalHttp.Location, h.logoutRedirect)
		} else {
			w.Header().Set(internalHttp.Location, r.RequestURI)
		}

		w.WriteHeader(http.StatusSeeOther)
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

// isLocalRedirect returns whether the redirect points to a path on this server,
// to avoid an open redirect to external hosts provided via form value.
func isLocalRedirect(redirect string) bool {
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") || strings.Contains(redirect, "\\") {
		return false
	}
	parsedRedirect, parseError := url.Parse(redirect)
	return parseError == nil && parsedRedirect.Scheme == "" && parsedRedirect.Host == ""
}
