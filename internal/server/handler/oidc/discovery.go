package oidc

import (
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/pkce"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type oidcConfigurationResponse struct {
	Issuer                                    string                     `json:"issuer"`
	AuthorizationEndpoint                     string                     `json:"authorization_endpoint"`
	TokenEndpoint                             string                     `json:"token_endpoint"`
	UserInfoEndpoint                          string                     `json:"userinfo_endpoint,omitempty"`
	JWKsUri                                   string                     `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                      string                     `json:"registration_endpoint,omitempty"`
	ScopesSupported                           []string                   `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                    []oauth2.ResponseType      `json:"response_types_supported"`
	ResponseModesSupported                    []string                   `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                       []oauth2.GrantType         `json:"grant_types_supported,omitempty"`
	AcrValuesSupported                        []string                   `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                     []string                   `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported          []jwa.SignatureAlgorithm   `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported       []string                   `json:"id_token_encryption_alg_values_supported,omitempty"`
	IdTokenEncryptionEncValuesSupported       []string                   `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserInfoSigningAlgValuesSupported         []jwa.SignatureAlgorithm   `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserInfoEncryptionAlgValuesSupported      []string                   `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserInfoEncryptionEncValuesSupported      []string                   `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported    []jwa.SignatureAlgorithm   `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported []string                   `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string                   `json:"request_object_encryption_enc_values_supported,omitempty"`
	DisplayValuesSupported                    []string                   `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                       []string                   `json:"claim_types_supported,omitempty"`
	ClaimsSupported                           []string                   `json:"claims_supported,omitempty"`
	ClaimsLocalesSupported                    []string                   `json:"claims_locales_supported,omitempty"`
	ClaimsParameterSupported                  []string                   `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                 bool                       `json:"request_parameter_supported,omitempty"`
	RequestUriParameterSupported              []string                   `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestUriRegistration             []string                   `json:"require_request_uri_registration,omitempty"`
	TokenEndpointAuthMethodsSupported         []string                   `json:"token_endpoint_auth_methods_supported,omitempty"`
	ServiceDocumentation                      string                     `json:"service_documentation,omitempty"`
	UILocalesSupported                        []string                   `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                               string                     `json:"op_policy_uri,omitempty"`
	OpTosUri                                  string                     `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                        string                     `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported    []string                   `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpoint                     string                     `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported []string                   `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported             []pkce.CodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
}

type DiscoveryHandler struct {
	config       *config.Config
	keyManager   *key.Manger
	errorHandler *errorHandler.Handler
}

func NewOidcDiscoveryHandler(keyManager *key.Manger) *DiscoveryHandler {
	return &DiscoveryHandler{
		config:       config.GetConfigInstance(),
		keyManager:   keyManager,
		errorHandler: errorHandler.NewErrorHandler(),
	}
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if !h.config.GetOidc() {
		h.errorHandler.NotFoundHandler(w, r)
		return
	}
	if r.Method == http.MethodGet {
		endpointURL := func(endpointPath string) string {
			endpointURLString, endpointURLError := h.config.GetEndpointURL(endpointPath)
			if endpointURLError != nil {
				log.Error("Could not create URL for endpoint %s: %v", endpointPath, endpointURLError)
			}
			return endpointURLString
		}

		// OAuth2
		authorizationEndpoint := endpointURL(endpoint.Authorization)
		tokenEndpoint := endpointURL(endpoint.Token)

		// OAuth2 extensions
		introspectEndpoint := endpointURL(endpoint.Introspect)
		revokeEndpoint := endpointURL(endpoint.Revoke)
		keysEndpoint := endpointURL(endpoint.Keys)

		// OIDC 1.0 Core
		userInfoEndpoint := endpointURL(endpoint.OidcUserInfo)

		authMethodsSupported := []string{
			"client_secret_basic",
			"client_secret_post",
		}

		metadataResponse := &oidcConfigurationResponse{
			Issuer:                        h.config.GetIssuer(),
			AuthorizationEndpoint:         authorizationEndpoint,
			TokenEndpoint:                 tokenEndpoint,
			IntrospectionEndpoint:         introspectEndpoint,
			RevocationEndpoint:            revokeEndpoint,
			JWKsUri:                       keysEndpoint,
			UserInfoEndpoint:              userInfoEndpoint,
			ServiceDocumentation:          "https://stopnik.webish.dev",
			CodeChallengeMethodsSupported: h.codeChallengeMethods(),
			GrantTypesSupported:           h.config.GetSupportedGrantTypes(),
			ResponseTypesSupported:        h.config.GetSupportedResponseTypes(),
			ResponseModesSupported: []string{
				"query",
				"fragment",
			},
			TokenEndpointAuthMethodsSupported:         authMethodsSupported,
			IntrospectionEndpointAuthMethodsSupported: authMethodsSupported,
			RevocationEndpointAuthMethodsSupported:    authMethodsSupported,
			IdTokenSigningAlgValuesSupported:          h.keyManager.GetSigningAlgorithms(),
			SubjectTypesSupported:                     []string{"public"},
			ScopesSupported:                           []string{oidc.ScopeOpenId, oidc.ScopeProfile, oidc.ScopeAddress, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess},
		}
		jsonError := internalHttp.SendJson(metadataResponse, w, r)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r, jsonError)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

// codeChallengeMethods returns the supported PKCE methods, plain only when a loaded client is allowed to use it.
func (h *DiscoveryHandler) codeChallengeMethods() []pkce.CodeChallengeMethod {
	if h.config.GetPkcePlainAllowed() {
		return []pkce.CodeChallengeMethod{pkce.S256, pkce.PLAIN}
	}
	return []pkce.CodeChallengeMethod{pkce.S256}
}
