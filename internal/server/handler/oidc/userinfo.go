package oidc

import (
	"encoding/json"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/token"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type UserInfoHandler struct {
	tokenManager *token.Manager
	errorHandler *errorHandler.Handler
}

func NewOidcUserInfoHandler(tokenManager *token.Manager) *UserInfoHandler {
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
		user, client, _, valid := h.tokenManager.ValidateAccessToken(authorizationHeader)
		if valid {
			userInfoResponse = &user.Profile
			userInfoResponse.Subject = user.Username
			userInfoResponse.PreferredUserName = user.GetPreferredUsername()
			userInfoResponse.Name = userInfoResponse.GivenName + " " + userInfoResponse.FamilyName
			userInfoResponse.Address.Formatted = user.GetFormattedAddress()
		} else {
			userInfoResponse = &config.UserProfile{}
		}

		var result interface{}
		result = userInfoResponse

		if valid {
			roles := user.GetRoles(client.Id)
			if len(roles) != 0 {
				updateResult, updateError := updateRoles(userInfoResponse, client.GetRolesClaim(), roles)
				if updateError == nil {
					result = updateResult
				}
			}
		}

		jsonError := internalHttp.SendJson(result, w)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func updateRoles(userProfile *config.UserProfile, rolesName string, roles []string) (map[string]interface{}, error) {
	marshaledUserProfile, marshalError := json.Marshal(userProfile)
	if marshalError != nil {
		return nil, marshalError
	}

	var a map[string]interface{}
	unmarshalError := json.Unmarshal(marshaledUserProfile, &a)
	if unmarshalError != nil {
		return nil, unmarshalError
	}

	a[rolesName] = roles

	return a, nil
}
