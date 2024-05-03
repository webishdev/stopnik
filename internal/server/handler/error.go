package handler

import (
	"log"
	"net/http"
)

func MethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusMethodNotAllowed, "405 Method not allowed", w)
}

func ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusForbidden, "403 Forbidden", w)
}

func InternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusInternalServerError, "500 Internal Server Error", w)
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusNotFound, "404 Not Found", w)
}

func NoContentHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusNoContent, "204 No content", w)
}

func SeeOtherHandler(w http.ResponseWriter, r *http.Request) {
	sendStatus(http.StatusSeeOther, "303 see other", w)
}

func sendStatus(status int, message string, w http.ResponseWriter) {
	w.WriteHeader(status)
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Printf("Could not send status message: %v", err)
	}
}
