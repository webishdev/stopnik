package handler

import (
	"net/http"
	internalHttp "stopnik/internal/http"
	"stopnik/log"
)

type LogoutHandler struct {
	logoutRedirect string
	cookieManager  *internalHttp.CookieManager
}

func CreateLogoutHandler(cookieManager *internalHttp.CookieManager, logoutRedirect string) *LogoutHandler {
	return &LogoutHandler{
		cookieManager:  cookieManager,
		logoutRedirect: logoutRedirect,
	}
}

func (handler *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		_, validCookie := handler.cookieManager.ValidateCookie(r)
		if !validCookie {
			ForbiddenHandler(w, r)
			return
		}
		cookie := handler.cookieManager.DeleteCookie()

		http.SetCookie(w, &cookie)

		logoutRedirectFrom := r.PostFormValue("stopnik_logout_redirect")

		if logoutRedirectFrom != "" {
			w.Header().Set(internalHttp.Location, logoutRedirectFrom)
		} else if handler.logoutRedirect != "" {
			w.Header().Set(internalHttp.Location, handler.logoutRedirect)
		} else {
			w.Header().Set(internalHttp.Location, r.RequestURI)
		}

		w.WriteHeader(http.StatusSeeOther)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
