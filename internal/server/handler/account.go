package handler

import (
	"github.com/google/uuid"
	"net/http"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/server/auth"
	"stopnik/internal/template"
	"stopnik/log"
)

type AccountHandler struct {
	config *config.Config
}

func CreateAccountHandler(config *config.Config) *AccountHandler {
	return &AccountHandler{
		config: config,
	}
}

func (handler *AccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		_, validCookie := internalHttp.ValidateCookie(handler.config, r)
		if validCookie {
			logoutTemplate := template.LogoutTemplate()

			_, err := w.Write(logoutTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		} else {
			id := uuid.New()
			loginTemplate := template.LoginTemplate(id.String(), "account")

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		}
	} else if r.Method == http.MethodPost {
		// Handle POST from login
		user, userExists := auth.UserBasicAuth(handler.config, r)
		if !userExists {
			w.Header().Set(internalHttp.Location, r.RequestURI)
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		cookie, err := internalHttp.CreateCookie(handler.config, user.Username)
		if err != nil {
			InternalServerErrorHandler(w, r)
			return
		}

		http.SetCookie(w, &cookie)

		w.Header().Set(internalHttp.Location, r.RequestURI)
		w.WriteHeader(http.StatusSeeOther)
		return

	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
