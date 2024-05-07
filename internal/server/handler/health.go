package handler

import (
	"net/http"
	"stopnik/internal/server/json"
	"stopnik/log"
)

type Health struct {
	Ping string `json:"ping"`
}

type HealthHandler struct{}

func (handler *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		healthResponse := Health{Ping: "pong"}

		jsonError := json.SendJson(healthResponse, w)
		if jsonError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
