package oidc

import (
	internalHttp "github.com/webishdev/stopnik/internal/http"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type UserInfo struct {
}

type UserInfoHandler struct {
	errorHandler *errorHandler.Handler
}

func NewOidcUserInfoHandler() *UserInfoHandler {
	return &UserInfoHandler{
		errorHandler: errorHandler.NewErrorHandler(),
	}
}

func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		userInfoResponse := &UserInfo{}
		jsonError := internalHttp.SendJson(userInfoResponse, w)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
