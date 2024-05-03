package handler

import "net/http"

type LogoutHandler struct{}

func CreateLogoutHandler() *LogoutHandler {
	return &LogoutHandler{}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

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
}
