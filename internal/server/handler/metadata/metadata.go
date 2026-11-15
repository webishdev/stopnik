package metadata

import (
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type response struct {
	Issuer                                    string                     `json:"issuer"`
	AuthorizationEndpoint                     string                     `json:"authorization_endpoint"`
	TokenEndpoint                             string                     `json:"token_endpoint"`
	JWKsUri                                   string                     `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                      string                     `json:"registration_endpoint,omitempty"`
	ScopesSupported                           []string                   `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                    []oauth2.ResponseType      `json:"response_types_supported,omitempty"`
	ResponseModesSupported                    []string                   `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                       []oauth2.GrantType         `json:"grant_types_supported,omitempty"`
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

type Handler struct {
	config       *config.Config
	keyManager   *key.Manger
	errorHandler *errorHandler.Handler
}

func NewMetadataHandler(keyManager *key.Manger) *Handler {
	return &Handler{
		config:       config.GetConfigInstance(),
		keyManager:   keyManager,
		errorHandler: errorHandler.NewErrorHandler(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
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

		authMethodsSupported := []string{
			"client_secret_basic",
			"client_secret_post",
		}

		metadataResponse := &response{
			Issuer:                        h.config.GetIssuer(),
			AuthorizationEndpoint:         authorizationEndpoint,
			TokenEndpoint:                 tokenEndpoint,
			IntrospectionEndpoint:         introspectEndpoint,
			RevocationEndpoint:            revokeEndpoint,
			JWKsUri:                       keysEndpoint,
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
func (h *Handler) codeChallengeMethods() []pkce.CodeChallengeMethod {
	if h.config.GetPkcePlainAllowed() {
		return []pkce.CodeChallengeMethod{pkce.S256, pkce.PLAIN}
	}
	return []pkce.CodeChallengeMethod{pkce.S256}
}
