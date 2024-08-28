package oidc

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/endpoint"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_OidcConfiguration(t *testing.T) {
	testOidcConfiguration(t)
	testOidcConfigurationNotAllowedHttpMethods(t)
}

func testOidcConfiguration(t *testing.T) {
	t.Run("Get OIDC configuration", func(t *testing.T) {
		oidcDiscoveryHandler := NewOidcDiscoveryHandler()

		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)

		oidcDiscoveryHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		requestResponse := rr.Result()

		oidcConfigurationParse := testOidcConfigurationParse(t, requestResponse)

		if oidcConfigurationParse.Issuer != "http://example.com" {
			t.Error("oidcConfigurationParse issuer did not match")
		}

		if oidcConfigurationParse.AuthorizationEndpoint != "http://example.com/authorize" {
			t.Error("oidcConfigurationParse authorization_endpoint did not match")
		}

		if oidcConfigurationParse.TokenEndpoint != "http://example.com/token" {
			t.Error("oidcConfigurationParse token_endpoint did not match")
		}

		if oidcConfigurationParse.JWKsUri != "http://example.com/keys" {
			t.Error("oidcConfigurationParse jwks_uri did not match")
		}

		if oidcConfigurationParse.IntrospectionEndpoint != "http://example.com/introspect" {
			t.Error("oidcConfigurationParse introspection_endpoint did not match")
		}

		if oidcConfigurationParse.RevocationEndpoint != "http://example.com/revoke" {
			t.Error("oidcConfigurationParse revocation_endpoint did not match")
		}

		if oidcConfigurationParse.ServiceDocumentation != "https://stopnik.webish.dev" {
			t.Error("oidcConfigurationParse service_documentation did not match")
		}
	})
}

func testOidcConfigurationNotAllowedHttpMethods(t *testing.T) {
	var testInvalidOidcConfigurationHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidOidcConfigurationHttpMethods {
		testMessage := fmt.Sprintf("OIDC configuration with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
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
