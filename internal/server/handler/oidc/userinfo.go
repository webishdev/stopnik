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

type UserInfoResponse struct {
	config.UserProfile
	config.UserInformation
}

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
		response := &UserInfoResponse{}
		validAccessToken, valid := h.tokenManager.ValidateAccessTokenRequest(r)
		if valid {
			user := validAccessToken.User
			client := validAccessToken.Client
			scopes := validAccessToken.Scopes
			requestedClaims := validAccessToken.RequestedClaims
			response.Subject = user.Username

			applyProfileClaims(user, scopes, requestedClaims, response)
			applyAddressClaims(user, scopes, requestedClaims, response)
			applyEmailClaims(user, scopes, requestedClaims, response)
			applyPhoneClaims(user, scopes, requestedClaims, response)

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
			h.errorHandler.BadRequestHandler(w, r)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func applyPhoneClaims(user *config.User, scopes []string, requestedClaims *oidc.ClaimsParameter, response *UserInfoResponse) {
	applyClaim(scopes, oidc.ScopePhone, requestedClaims, oidc.ClaimPhoneNumber, func() {
		response.PhoneNumber = user.UserInformation.PhoneNumber
	})
	applyClaim(scopes, oidc.ScopePhone, requestedClaims, oidc.ClaimPhoneNumberVerified, func() {
		response.PhoneVerified = user.UserInformation.PhoneVerified
	})
}

func applyEmailClaims(user *config.User, scopes []string, requestedClaims *oidc.ClaimsParameter, response *UserInfoResponse) {
	applyClaim(scopes, oidc.ScopeEmail, requestedClaims, oidc.ClaimEmail, func() {
		response.Email = user.UserInformation.Email
	})
	applyClaim(scopes, oidc.ScopeEmail, requestedClaims, oidc.ClaimEmailVerified, func() {
		response.EmailVerified = user.UserInformation.EmailVerified
	})
}

func applyAddressClaims(user *config.User, scopes []string, requestedClaims *oidc.ClaimsParameter, response *UserInfoResponse) {
	if user.UserInformation.Address != nil {
		applyClaim(scopes, oidc.ScopeAddress, requestedClaims, oidc.ClaimAddressFormatted, func() {
			if response.Address == nil {
				response.Address = &config.UserAddress{}
			}
			response.Address.Formatted = user.GetFormattedAddress()
		})
		applyClaim(scopes, oidc.ScopeAddress, requestedClaims, oidc.ClaimAddressStreetAddress, func() {
			if response.Address == nil {
				response.Address = &config.UserAddress{}
			}
			response.Address.Street = user.UserInformation.Address.Street
		})
		applyClaim(scopes, oidc.ScopeAddress, requestedClaims, oidc.ClaimAddressLocality, func() {
			if response.Address == nil {
				response.Address = &config.UserAddress{}
			}
			response.Address.City = user.UserInformation.Address.City
		})
		applyClaim(scopes, oidc.ScopeAddress, requestedClaims, oidc.ClaimAddressPostalCode, func() {
			if response.Address == nil {
				response.Address = &config.UserAddress{}
			}
			response.Address.PostalCode = user.UserInformation.Address.PostalCode
		})
		applyClaim(scopes, oidc.ScopeAddress, requestedClaims, oidc.ClaimAddressRegion, func() {
			if response.Address == nil {
				response.Address = &config.UserAddress{}
			}
			response.Address.Region = user.UserInformation.Address.Region
		})
		applyClaim(scopes, oidc.ScopeAddress, requestedClaims, oidc.ClaimAddressCountry, func() {
			if response.Address == nil {
				response.Address = &config.UserAddress{}
			}
			response.Address.Country = user.UserInformation.Address.Country
		})
	}
}

func applyProfileClaims(user *config.User, scopes []string, requestedClaims *oidc.ClaimsParameter, response *UserInfoResponse) {
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimName, func() {
		response.Name = user.GetName()
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimGivenName, func() {
		response.GivenName = user.UserProfile.GivenName
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimMiddleName, func() {
		response.MiddleName = user.UserProfile.MiddleName
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimFamilyName, func() {
		response.FamilyName = user.UserProfile.FamilyName
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimNickname, func() {
		response.Nickname = user.UserProfile.Nickname
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimPreferredUsername, func() {
		response.PreferredUserName = user.GetPreferredUsername()
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimGender, func() {
		response.Gender = user.UserProfile.Gender
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimBirthdate, func() {
		response.BirthDate = user.UserProfile.BirthDate
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimZoneInfo, func() {
		response.ZoneInfo = user.UserProfile.ZoneInfo
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimLocale, func() {
		response.Locale = user.UserProfile.Locale
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimWebsite, func() {
		response.Website = user.UserProfile.Website
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimProfile, func() {
		response.Profile = user.UserProfile.Profile
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimPicture, func() {
		response.Picture = user.UserProfile.Picture
	})
	applyClaim(scopes, oidc.ScopeProfile, requestedClaims, oidc.ClaimUpdatedAt, func() {
		response.UpdatedAt = system.GetStartTime().Unix()
	})
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

func applyClaim(scopes []string, scope string, requestedClaims *oidc.ClaimsParameter, name string, consumer func()) {
	if slices.Contains(scopes, scope) || oidc.HasUserInfoClaim(requestedClaims, name) {
		consumer()
	}
}
