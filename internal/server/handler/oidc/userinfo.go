package oidc

import (
	"encoding/json"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oidc"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"slices"
)

type UserInfoResponse struct {
	config.UserProfile
	config.UserInformation
}

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
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		response := &oidc.UserInfoResponse{}
		user, client, scopes, valid := h.tokenManager.ValidateAccessTokenRequest(r)
		if valid {
			response.Subject = user.Username
			if slices.Contains(scopes, oidc.ScopeProfile) {
				response.Name = user.GetName()
				response.GivenName = user.UserProfile.GivenName
				response.FamilyName = user.UserProfile.FamilyName
				response.Nickname = user.UserProfile.Nickname
				response.PreferredUserName = user.GetPreferredUsername()
				response.Gender = user.UserProfile.Gender
				response.BirthDate = user.UserProfile.BirthDate
				response.ZoneInfo = user.UserProfile.ZoneInfo
				response.Locale = user.UserProfile.Locale
				response.Website = user.UserProfile.Website
				response.Profile = user.UserProfile.Profile
				response.Picture = user.UserProfile.Picture
				response.UpdatedAt = user.UserProfile.UpdatedAt
			}

			if slices.Contains(scopes, oidc.ScopeAddress) && user.UserInformation.Address != nil {
				response.Address = &config.UserAddress{}
				response.Address.Formatted = user.GetFormattedAddress()
				response.Address.Street = user.UserInformation.Address.Street
				response.Address.City = user.UserInformation.Address.City
				response.Address.PostalCode = user.UserInformation.Address.PostalCode
				response.Address.Region = user.UserInformation.Address.Region
				response.Address.Country = user.UserInformation.Address.Country
			}

			if slices.Contains(scopes, oidc.ScopeEmail) {
				response.Email = user.UserInformation.Email
				response.EmailVerified = user.UserInformation.EmailVerified
			}

			if slices.Contains(scopes, oidc.ScopePhone) {
				response.PhoneNumber = user.UserInformation.PhoneNumber
				response.PhoneVerified = user.UserInformation.PhoneVerified
			}

		} else {
			h.errorHandler.BadRequestHandler(w, r)
			return
		}

		var result interface{}
		result = response

		roles := user.GetRoles(client.Id)
		if len(roles) != 0 {
			updateResult, updateError := updateRoles(response, client.GetRolesClaim(), roles)
			if updateError == nil {
				result = updateResult
			}
		}

		jsonError := internalHttp.SendJson(result, w, r)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func updateRoles(userProfile *oidc.UserInfoResponse, rolesName string, roles []string) (map[string]interface{}, error) {
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
