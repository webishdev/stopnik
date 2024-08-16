package metadata

import (
	"fmt"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	errorHandler "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/log"
	"net/http"
	"net/url"
)

type response struct {
	Issuer                                             string   `json:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint"`
	TokenEndpoint                                      string   `json:"token_endpoint"`
	JWKsUri                                            string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string `json:"response_types_supported,omitempty"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty"`
	UILocalesSupported                                 []string `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        string   `json:"op_policy_uri,omitempty"`
	OpTosUri                                           string   `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
}

type requestData struct {
	scheme   string
	host     string
	path     string
	query    string
	fragment string
}

type Handler struct {
	errorHandler *errorHandler.Handler
}

func CreateMetadataHandler() *Handler {
	return &Handler{}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {
		requestData := newRequestData(r)
		urlFromRequest, parseError := requestData.URL()
		if parseError != nil {
			h.errorHandler.InternalServerErrorHandler(w, r)
			return
		}
		authorizationEndpoint := urlFromRequest.JoinPath("/authorize")
		tokenEndpoint := urlFromRequest.JoinPath("/token")
		metadataResponse := &response{
			Issuer:                requestData.IssuerString(),
			AuthorizationEndpoint: authorizationEndpoint.String(),
			TokenEndpoint:         tokenEndpoint.String(),
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

func newRequestData(r *http.Request) *requestData {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	fragment := ""
	if r.URL.RawFragment != "" {
		fragment = "#" + r.URL.RawFragment
	}
	return &requestData{
		scheme:   scheme,
		host:     r.Host,
		path:     r.URL.RawPath,
		query:    query,
		fragment: fragment,
	}
}

func (r *requestData) IssuerString() string {
	return fmt.Sprintf("%s://%s", r.scheme, r.host)
}

func (r *requestData) URL() (*url.URL, error) {
	uri := fmt.Sprintf("%s://%s%s%s%s", r.scheme, r.host, r.path, r.query, r.fragment)

	return url.Parse(uri)
}
