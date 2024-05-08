package handler

import (
	"net/http"
	internalHttp "stopnik/internal/http"
	"stopnik/log"
)

type LogoutHandler struct {
	cookieManager *internalHttp.CookieManager
}

func CreateLogoutHandler(cookieManager *internalHttp.CookieManager) *LogoutHandler {
	return &LogoutHandler{
		cookieManager: cookieManager,
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

		//if handler.config.Server.LogoutRedirect == "" {
		//	w.Header().Set(internalHttp.Location, r.URL.RequestURI())
		//} else {
		//	w.Header().Set(internalHttp.Location, handler.config.Server.LogoutRedirect)
		//}

		w.WriteHeader(http.StatusSeeOther)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
