package handler

import (
	"github.com/google/uuid"
	"net/http"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/server/validation"
	"stopnik/internal/template"
	"stopnik/log"
)

type AccountHandler struct {
	validator     *validation.RequestValidator
	cookieManager *internalHttp.CookieManager
}

func CreateAccountHandler(validator *validation.RequestValidator, cookieManager *internalHttp.CookieManager) *AccountHandler {
	return &AccountHandler{
		validator:     validator,
		cookieManager: cookieManager,
	}
}

func (handler *AccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		user, validCookie := handler.cookieManager.ValidateCookie(r)
		if validCookie {
			logoutTemplate := template.LogoutTemplate(user.Username, r.RequestURI)

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
		user, userExists := handler.validator.ValidateFormLogin(r)
		if !userExists {
			w.Header().Set(internalHttp.Location, r.RequestURI)
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		cookie, err := handler.cookieManager.CreateCookie(user.Username)
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
