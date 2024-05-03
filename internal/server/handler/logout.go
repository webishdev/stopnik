package handler

import (
	"net/http"
	"stopnik/internal/template"
)

type LogoutHandler struct{}

func CreateLogoutHandler() *LogoutHandler {
	return &LogoutHandler{}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		cookie := http.Cookie{
			Name:     "STOPIK_AUTH",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		http.SetCookie(w, &cookie)
		w.WriteHeader(http.StatusNoContent)
	} else if r.Method == http.MethodGet {
		_, noCookieError := r.Cookie("STOPIK_AUTH")
		if noCookieError == nil {
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
		MethodNotSupportedHandler(w, r)
		return
	}
}
