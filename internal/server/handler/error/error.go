package error

import (
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type RequestHandler struct{}

func NewErrorHandler() *RequestHandler {
	return &RequestHandler{}
}

func (requestHandler *RequestHandler) MethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusMethodNotAllowed, "405 Method not allowed", w, r)
}

func (requestHandler *RequestHandler) BadRequestHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusBadRequest, "400 Bad Request", w, r)
}

func (requestHandler *RequestHandler) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusForbidden, "403 Forbidden", w, r)
}

func (requestHandler *RequestHandler) InternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusInternalServerError, "500 Internal Server Error", w, r)
}

func (requestHandler *RequestHandler) NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusNotFound, "404 Not Found", w, r)
}

func (requestHandler *RequestHandler) NoContentHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusNoContent, "204 No content", w, r)
}

func (requestHandler *RequestHandler) SeeOtherHandler(w http.ResponseWriter, r *http.Request) {
	requestHandler.sendStatus(http.StatusSeeOther, "303 see other", w, r)
}

func (requestHandler *RequestHandler) sendStatus(status int, message string, w http.ResponseWriter, r *http.Request) {
	log.AccessLogResult(r, status, message)
	w.WriteHeader(status)
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Error("Could not send status message: %v", err)
	}
}
