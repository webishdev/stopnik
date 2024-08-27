package logout

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type Handler struct {
	logoutRedirect string
	cookieManager  *manager.CookieManager
	errorHandler   *error.Handler
}

func NewLogoutHandler(cookieManager *manager.CookieManager, logoutRedirect string) *Handler {
	return &Handler{
		cookieManager:  cookieManager,
		logoutRedirect: logoutRedirect,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		_, validCookie := h.cookieManager.ValidateAuthCookie(r)
		if !validCookie {
			h.errorHandler.ForbiddenHandler(w, r)
			return
		}
		cookie := h.cookieManager.DeleteAuthCookie()

		http.SetCookie(w, &cookie)

		logoutRedirectFrom := r.PostFormValue("stopnik_logout_redirect")

		if logoutRedirectFrom != "" {
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
