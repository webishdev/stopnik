package health

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type Health struct {
	Ping     string   `json:"ping"`
	Username string   `json:"username,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

type Handler struct {
	tokenManager *token.Manager
	errorHandler *error.Handler
}

func NewHealthHandler(tokenManager *token.Manager) *Handler {
	return &Handler{
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		healthResponse := Health{Ping: "pong"}

		validAccessToken, valid := h.tokenManager.ValidateAccessTokenRequest(r)
		if valid {
			healthResponse.Username = validAccessToken.User.Username
			healthResponse.Scopes = validAccessToken.Scopes
		}

		jsonError := internalHttp.SendJson(healthResponse, w, r)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
