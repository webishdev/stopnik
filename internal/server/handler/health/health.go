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
	tokenManager *token.TokenManager
	errorHandler *error.Handler
}

func NewHealthHandler(tokenManager *token.TokenManager) *Handler {
	return &Handler{
		tokenManager: tokenManager,
		errorHandler: error.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		healthResponse := Health{Ping: "pong"}

		authorizationHeader := r.Header.Get(internalHttp.Authorization)
		user, _, scopes, valid := h.tokenManager.ValidateAccessToken(authorizationHeader)
		if valid {
			healthResponse.Username = user.Username
			healthResponse.Scopes = scopes
		}

		jsonError := internalHttp.SendJson(healthResponse, w)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
