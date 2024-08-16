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

type Handler struct {
	validator       *validation.RequestValidator
	cookieManager   *internalHttp.CookieManager
	templateManager *template.Manager
	errorHandler    *error.Handler
}

func CreateAccountHandler(
	validator *validation.RequestValidator,
	cookieManager *internalHttp.CookieManager,
	templateManager *template.Manager,
) *Handler {
	return &Handler{
		validator:       validator,
		cookieManager:   cookieManager,
		templateManager: templateManager,
		errorHandler:    error.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		user, validCookie := h.cookieManager.ValidateCookie(r)
		if validCookie {
			logoutTemplate := h.templateManager.LogoutTemplate(user.Username, r.RequestURI)

			_, err := w.Write(logoutTemplate.Bytes())
			if err != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}
		} else {
			id := uuid.New()
			loginTemplate := h.templateManager.LoginTemplate(id.String(), "account")

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}
		}
	} else if r.Method == http.MethodPost {
		// Handle POST from login
		user, userExists := h.validator.ValidateFormLogin(r)
		if !userExists {
			w.Header().Set(internalHttp.Location, r.RequestURI)
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		cookie, err := h.cookieManager.CreateCookie(user.Username)
		if err != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}

		http.SetCookie(w, &cookie)

		w.Header().Set(internalHttp.Location, r.RequestURI)
		w.WriteHeader(http.StatusSeeOther)
		return

	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
