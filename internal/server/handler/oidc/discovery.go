package oidc

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
)

type response struct {
	Issuer                                             string                     `json:"issuer"`
	AuthorizationEndpoint                              string                     `json:"authorization_endpoint"`
	TokenEndpoint                                      string                     `json:"token_endpoint"`
	JWKsUri                                            string                     `json:"jwks_uri,omitempty"`
	UserInfoEndpoint                                   string                     `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint                               string                     `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string                   `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []oauth2.ResponseType      `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string                   `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []oauth2.GrantType         `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string                   `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []jwa.SignatureAlgorithm   `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string                     `json:"service_documentation,omitempty"`
	UILocalesSupported                                 []string                   `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        string                     `json:"op_policy_uri,omitempty"`
	OpTosUri                                           string                     `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string                     `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string                   `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []jwa.SignatureAlgorithm   `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string                     `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string                   `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []jwa.SignatureAlgorithm   `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []pkce.CodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
}

type DiscoveryHandler struct {
	errorHandler *errorHandler.Handler
}

func NewOidcDiscoveryHandler() *DiscoveryHandler {
	return &DiscoveryHandler{
		errorHandler: errorHandler.NewErrorHandler(),
	}
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		requestData := internalHttp.NewRequestData(r)
		urlFromRequest, parseError := requestData.URL()
		if parseError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}

		// OAuth2
		authorizationEndpoint := urlFromRequest.JoinPath(endpoint.Authorization)
		tokenEndpoint := urlFromRequest.JoinPath(endpoint.Token)

		// OAuth2 extensions
		introspectEndpoint := urlFromRequest.JoinPath(endpoint.Introspect)
		revokeEndpoint := urlFromRequest.JoinPath(endpoint.Revoke)
		keysEndpoint := urlFromRequest.JoinPath(endpoint.Keys)

		// OIDC 1.0 Core
		userInfoEndpoint := urlFromRequest.JoinPath(endpoint.OidcUserInfo)

		authMethodsSupported := []string{
			"client_secret_basic",
			"client_secret_post",
		}

		signatureAlgorithmSupported := []jwa.SignatureAlgorithm{
			jwa.RS256,
			jwa.ES256,
			jwa.ES384,
			jwa.ES512,
			jwa.HS256,
		}

		metadataResponse := &response{
			Issuer:                requestData.IssuerString(),
			AuthorizationEndpoint: authorizationEndpoint.String(),
			TokenEndpoint:         tokenEndpoint.String(),
			IntrospectionEndpoint: introspectEndpoint.String(),
			RevocationEndpoint:    revokeEndpoint.String(),
			JWKsUri:               keysEndpoint.String(),
			UserInfoEndpoint:      userInfoEndpoint.String(),
			ServiceDocumentation:  "https://stopnik.webish.dev",
			CodeChallengeMethodsSupported: []pkce.CodeChallengeMethod{
				pkce.PLAIN,
				pkce.S256,
			},
			GrantTypesSupported: []oauth2.GrantType{
				oauth2.GtAuthorizationCode,
				oauth2.GtClientCredentials,
				oauth2.GtPassword,
				oauth2.GtRefreshToken,
				oauth2.GtImplicit,
			},
			ResponseTypesSupported: []oauth2.ResponseType{
				oauth2.RtCode,
				oauth2.RtToken,
			},
			ResponseModesSupported: []string{
				"query",
				"fragment",
			},
			TokenEndpointAuthMethodsSupported:                  authMethodsSupported,
			TokenEndpointAuthSigningAlgValuesSupported:         signatureAlgorithmSupported,
			IntrospectionEndpointAuthMethodsSupported:          authMethodsSupported,
			IntrospectionEndpointAuthSigningAlgValuesSupported: signatureAlgorithmSupported,
			RevocationEndpointAuthMethodsSupported:             authMethodsSupported,
			RevocationEndpointAuthSigningAlgValuesSupported:    signatureAlgorithmSupported,
		}
		jsonError := internalHttp.SendJson(metadataResponse, w)
		if jsonError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}
