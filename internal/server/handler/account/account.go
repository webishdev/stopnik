package account

import (
	"github.com/google/uuid"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type AccountHandler struct {
	validator       *validation.RequestValidator
	cookieManager   *internalHttp.CookieManager
	templateManager *template.Manager
	errorHandler    *error.RequestHandler
}

func CreateAccountHandler(
	validator *validation.RequestValidator,
	cookieManager *internalHttp.CookieManager,
	templateManager *template.Manager,
) *AccountHandler {
	return &AccountHandler{
		validator:       validator,
		cookieManager:   cookieManager,
		templateManager: templateManager,
		errorHandler:    error.NewErrorHandler(),
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
				handler.errorHandler.InternalServerErrorHandler(w, r)
				return
			}
		} else {
			id := uuid.New()
			loginTemplate := handler.templateManager.LoginTemplate(id.String(), "account")

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				handler.errorHandler.InternalServerErrorHandler(w, r)
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
			handler.errorHandler.InternalServerErrorHandler(w, r)
			return
		}

		http.SetCookie(w, &cookie)

		w.Header().Set(internalHttp.Location, r.RequestURI)
		w.WriteHeader(http.StatusSeeOther)
		return

	} else {
		handler.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
