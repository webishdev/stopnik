package handler

import (
	"net/http"
	"stopnik/log"
)

type HomeHandler struct{}

func (handler *HomeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	_, err := w.Write([]byte("Hello world!"))
	if err != nil {
		return
	}
}
