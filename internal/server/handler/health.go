package handler

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/store"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type Health struct {
	Ping     string   `json:"ping"`
	Username string   `json:"username,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

type HealthHandler struct {
	tokenManager *store.TokenManager
}

func NewHealthHandler(tokenManager *store.TokenManager) *HealthHandler {
	return &HealthHandler{tokenManager: tokenManager}
}

func (handler *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		healthResponse := Health{Ping: "pong"}

		authorizationHeader := r.Header.Get(internalHttp.Authorization)
		user, scopes, userExists := handler.tokenManager.ValidateAccessToken(authorizationHeader)
		if userExists {
			healthResponse.Username = user.Username
			healthResponse.Scopes = scopes
		}

		jsonError := internalHttp.SendJson(healthResponse, w)
		if jsonError != nil {
			InternalServerErrorHandler(w, r)
			return
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}
