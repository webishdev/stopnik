package oidc

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_OidcConfiguration(t *testing.T) {
	type basePathParameter struct {
		basePath       string
		expectedIssuer string
	}

	var basePathParameters = []basePathParameter{
		{basePath: "", expectedIssuer: "http://example.com"},
		{basePath: "/", expectedIssuer: "http://example.com"},
		{basePath: "/auth", expectedIssuer: "http://example.com/auth"},
		{basePath: "auth/", expectedIssuer: "http://example.com/auth"},
	}

	for _, test := range basePathParameters {
		testMessage := fmt.Sprintf("OIDC configuration with base path '%s'", test.basePath)
		t.Run(testMessage, func(t *testing.T) {
			initializeConfig(t, test.basePath)
			oidcDiscoveryHandler := NewOidcDiscoveryHandler()

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)

			oidcDiscoveryHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			requestResponse := rr.Result()

			oidcConfigurationParse := testOidcConfigurationParse(t, requestResponse)

			if oidcConfigurationParse.Issuer != test.expectedIssuer {
				t.Error("oidcConfigurationParse issuer did not match")
			}

			if oidcConfigurationParse.AuthorizationEndpoint != test.expectedIssuer+"/authorize" {
				t.Error("oidcConfigurationParse authorization_endpoint did not match")
			}

			if oidcConfigurationParse.TokenEndpoint != test.expectedIssuer+"/token" {
				t.Error("oidcConfigurationParse token_endpoint did not match")
			}

			if oidcConfigurationParse.JWKsUri != test.expectedIssuer+"/keys" {
				t.Error("oidcConfigurationParse jwks_uri did not match")
			}

			if oidcConfigurationParse.IntrospectionEndpoint != test.expectedIssuer+"/introspect" {
				t.Error("oidcConfigurationParse introspection_endpoint did not match")
			}

			if oidcConfigurationParse.RevocationEndpoint != test.expectedIssuer+"/revoke" {
				t.Error("oidcConfigurationParse revocation_endpoint did not match")
			}

			if oidcConfigurationParse.ServiceDocumentation != "https://stopnik.webish.dev" {
				t.Error("oidcConfigurationParse service_documentation did not match")
			}
		})
	}
}

func Test_OidcConfigurationNotAllowedHttpMethods(t *testing.T) {
	var testInvalidOidcConfigurationHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidOidcConfigurationHttpMethods {
		testMessage := fmt.Sprintf("OIDC configuration with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			initializeConfig(t, "")
			oidcDiscoveryHandler := NewOidcDiscoveryHandler()

			rr := httptest.NewRecorder()

			oidcDiscoveryHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Metadata, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testOidcConfigurationParse(t *testing.T, r *http.Response) oidcConfigurationResponse {
	responseBody, bodyReadErr := io.ReadAll(r.Body)

	if bodyReadErr != nil {
		t.Errorf("could not read oidcConfigurationResponse body: %v", bodyReadErr)
	}

	if responseBody == nil {
		t.Errorf("oidcConfigurationResponse body was nil")
	}

	oidcConfigurationResponse := oidcConfigurationResponse{}
	jsonParseError := json.Unmarshal(responseBody, &oidcConfigurationResponse)
	if jsonParseError != nil {
		t.Errorf("could not parse oidcConfigurationResponse body: %v", jsonParseError)
	}

	return oidcConfigurationResponse
}

func initializeConfig(t *testing.T, basePath string) {
	testConfig := &config.Config{
		Server: config.Server{
			BasePath: basePath,
		},
	}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
}
