package handler

import (
	"net/http"
	"stopnik/internal/config"
	httpHeader "stopnik/internal/http"
	"stopnik/internal/template"
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
		cookie := DeleteCookie(handler.config)

		http.SetCookie(w, &cookie)

		if handler.config.Server.LogoutRedirect == "" {
			w.Header().Set(httpHeader.Location, r.URL.RequestURI())
		} else {
			w.Header().Set(httpHeader.Location, handler.config.Server.LogoutRedirect)
		}

		w.WriteHeader(http.StatusSeeOther)
	} else if r.Method == http.MethodGet {
		_, validCookie := ValidateCookie(handler.config, r)
		if validCookie {
			logoutTemplate := template.LogoutTemplate()

			_, err := w.Write(logoutTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		} else {
			ForbiddenHandler(w, r)
			return
		}

	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
