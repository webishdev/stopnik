package oidc

import (
	"encoding/json"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oidc"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"slices"
)

type UserInfoHandler struct {
	config       *config.Config
	tokenManager *token.Manager
	errorHandler *errorHandler.Handler
}

func NewOidcUserInfoHandler(tokenManager *token.Manager) *UserInfoHandler {
	configInstance := config.GetConfigInstance()
	return &UserInfoHandler{
		config:       configInstance,
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
				response.MiddleName = user.UserProfile.MiddleName
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
				response.UpdatedAt = system.GetStartTime().Unix()
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

		claims := h.config.GetClaims(user.Username, client.Id, scopes)
		for _, claim := range claims {
			currentClaim := *claim
			name := currentClaim.GetName()
			values := currentClaim.GetValues()
			updateResult, updateError := updateResponse(result, name, values)
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

func updateResponse(response any, key string, value any) (map[string]any, error) {
	marshaledResponse, marshalError := json.Marshal(response)
	if marshalError != nil {
		return nil, marshalError
	}

	var updatedResponse map[string]any
	unmarshalError := json.Unmarshal(marshaledResponse, &updatedResponse)
	if unmarshalError != nil {
		return nil, unmarshalError
	}

	updatedResponse[key] = value

	return updatedResponse, nil
}
