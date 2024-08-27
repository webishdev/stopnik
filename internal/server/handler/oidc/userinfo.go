package oidc

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type UserInfoHandler struct {
	tokenManager *manager.TokenManager
	errorHandler *errorHandler.Handler
}

func NewOidcUserInfoHandler(tokenManager *manager.TokenManager) *UserInfoHandler {
	return &UserInfoHandler{
		tokenManager: tokenManager,
		errorHandler: errorHandler.NewErrorHandler(),
	}
}

func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		var userInfoResponse *config.UserProfile
		authorizationHeader := r.Header.Get(internalHttp.Authorization)
		user, _, userExists := h.tokenManager.ValidateAccessToken(authorizationHeader)
		if userExists {
			userInfoResponse = &user.Profile
			userInfoResponse.Subject = user.Username
			userInfoResponse.Name = userInfoResponse.GivenName + " " + userInfoResponse.FamilyName
		} else {
			userInfoResponse = &config.UserProfile{}
		}

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
