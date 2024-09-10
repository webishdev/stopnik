package error

import (
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type Handler struct{}

func NewErrorHandler() *Handler {
	return &Handler{}
}

func (h *Handler) MethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	h.sendStatus(http.StatusMethodNotAllowed, "405 Method not allowed", w, r)
}

func (h *Handler) BadRequestHandler(w http.ResponseWriter, r *http.Request) {
	h.sendStatus(http.StatusBadRequest, "400 Bad Request", w, r)
}

func (h *Handler) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	h.sendStatus(http.StatusForbidden, "403 Forbidden", w, r)
}

func (h *Handler) InternalServerErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	log.Error("Internal server error %s", err.Error())
	h.sendStatus(http.StatusInternalServerError, "500 Internal Server Error", w, r)
}

func (h *Handler) NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	h.sendStatus(http.StatusNotFound, "404 Not Found", w, r)
}

func (h *Handler) NoContentHandler(w http.ResponseWriter, r *http.Request) {
	h.sendStatus(http.StatusNoContent, "204 No content", w, r)
}

func (h *Handler) SeeOtherHandler(w http.ResponseWriter, r *http.Request) {
	h.sendStatus(http.StatusSeeOther, "303 see other", w, r)
}

func (h *Handler) sendStatus(status int, message string, w http.ResponseWriter, r *http.Request) {
	log.AccessLogResult(r, status, message)
	w.WriteHeader(status)
	_, err := w.Write([]byte(message))
	if err != nil {
		log.Error("Could not send status message: %v", err)
	}
}
