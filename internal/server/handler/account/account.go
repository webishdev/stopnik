package account

import (
	"github.com/google/uuid"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type Handler struct {
	validator           *validation.RequestValidator
	cookieManager       *cookie.Manager
	loginSessionManager session.LoginManager[session.LoginSession]
	templateManager     *template.Manager
	errorHandler        *error.Handler
}

func NewAccountHandler(
	validator *validation.RequestValidator,
	cookieManager *cookie.Manager,
	loginSessionManager session.LoginManager[session.LoginSession],
	templateManager *template.Manager,
) *Handler {
	return &Handler{
		validator:           validator,
		cookieManager:       cookieManager,
		loginSessionManager: loginSessionManager,
		templateManager:     templateManager,
		errorHandler:        error.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		user, _, validCookie := h.cookieManager.ValidateAuthCookie(r)
		if validCookie {
			logoutTemplate := h.templateManager.LogoutTemplate(user.Username, r.RequestURI)

			_, err := w.Write(logoutTemplate.Bytes())
			if err != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}
		} else {
			message := h.cookieManager.GetMessageCookieValue(r)

			id := uuid.NewString()
			loginToken := h.validator.NewLoginToken(id)
			loginTemplate := h.templateManager.LoginTemplate(loginToken, "account", message)

			_, err := w.Write(loginTemplate.Bytes())
			if err != nil {
				h.errorHandler.InternalServerErrorHandler(w, r)
				return
			}
		}
	} else if r.Method == http.MethodPost {
		// Handle POST from login
		user, loginError := h.validator.ValidateFormLogin(r)
		if loginError != nil {

			messageCookie := h.cookieManager.CreateMessageCookie(*loginError)
			http.SetCookie(w, &messageCookie)

			w.Header().Set(internalHttp.Location, r.RequestURI)
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		loginSession := &session.LoginSession{
			Id:       uuid.NewString(),
			Username: user.Username,
		}
		h.loginSessionManager.StartSession(loginSession)
		authCookie, err := h.cookieManager.CreateAuthCookie(user.Username, loginSession.Id)
		if err != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}

		http.SetCookie(w, &authCookie)

		w.Header().Set(internalHttp.Location, r.RequestURI)
		w.WriteHeader(http.StatusSeeOther)
		return

	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
