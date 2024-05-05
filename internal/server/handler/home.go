package handler

import (
	"net/http"
	"stopnik/log"
)

type HomeHandler struct{}

func (handler *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	_, err := w.Write([]byte("Hello STOPnik!"))
	if err != nil {
		InternalServerErrorHandler(w, r)
		return
	}
}
