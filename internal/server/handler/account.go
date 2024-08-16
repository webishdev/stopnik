package handler

import (
	"github.com/google/uuid"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type AccountHandler struct {
	validator       *validation.RequestValidator
	cookieManager   *internalHttp.CookieManager
	templateManager *template.TemplateManager
}

func CreateAccountHandler(
	validator *validation.RequestValidator,
	cookieManager *internalHttp.CookieManager,
	templateManager *template.TemplateManager,
) *AccountHandler {
	return &AccountHandler{
		validator:       validator,
		cookieManager:   cookieManager,
		templateManager: templateManager,
	}
}

func (handler *AccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		user, validCookie := handler.cookieManager.ValidateCookie(r)
		if validCookie {
			logoutTemplate := handler.templateManager.LogoutTemplate(user.Username, r.RequestURI)

			_, err := w.Write(logoutTemplate.Bytes())
			if err != nil {
				InternalServerErrorHandler(w, r)
				return
			}
		} else {
			id := uuid.New()
			loginTemplate := handler.templateManager.LoginTemplate(id.String(), "account")

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
