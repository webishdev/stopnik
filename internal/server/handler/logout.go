package handler

import (
	"net/http"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/log"
)

type LogoutHandler struct {
	config *config.Config
}

func CreateLogoutHandler(config *config.Config) *LogoutHandler {
	return &LogoutHandler{
		config: config,
	}
}

func (handler *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodPost {
		_, validCookie := httpHeader.ValidateCookie(handler.config, r)
		if !validCookie {
			ForbiddenHandler(w, r)
			return
		}
		cookie := httpHeader.DeleteCookie(handler.config)

		http.SetCookie(w, &cookie)

		if handler.config.Server.LogoutRedirect == "" {
			w.Header().Set(httpHeader.Location, r.URL.RequestURI())
		} else {
			w.Header().Set(httpHeader.Location, handler.config.Server.LogoutRedirect)
		}

		w.WriteHeader(http.StatusSeeOther)
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
