package handler

import (
	"net/http"
	"stopnik/log"
)

func MethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusMethodNotAllowed, "405 Method not allowed", w, r)
}

func ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusForbidden, "403 Forbidden", w, r)
}

func InternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusInternalServerError, "500 Internal Server Error", w, r)
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusNotFound, "404 Not Found", w, r)
}

func NoContentHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusNoContent, "204 No content", w, r)
}

func SeeOtherHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusSeeOther, "303 see other", w, r)
}

func sendStatus(status int, message string, w http.ResponseWriter, r *http.Request) {
	log.AccessLogResult(r, message)
	w.WriteHeader(status)
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Error("Could not send status message: %v", err)
	}
}
