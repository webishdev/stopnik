package metadata

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

func Test_Metadata(t *testing.T) {
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
		testMessage := fmt.Sprintf("Metadata with base path '%s'", test.basePath)
		t.Run(testMessage, func(t *testing.T) {
			initializeConfig(t, test.basePath)
			metadataHandler := NewMetadataHandler()

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)

			metadataHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			requestResponse := rr.Result()

			metadata := testMetadataParse(t, requestResponse)

			if metadata.Issuer != test.expectedIssuer {
				t.Error("metadata issuer did not match")
			}

			if metadata.AuthorizationEndpoint != test.expectedIssuer+"/authorize" {
				t.Error("metadata authorization_endpoint did not match")
			}

			if metadata.TokenEndpoint != test.expectedIssuer+"/token" {
				t.Error("metadata token_endpoint did not match")
			}

			if metadata.JWKsUri != test.expectedIssuer+"/keys" {
				t.Error("metadata jwks_uri did not match")
			}

			if metadata.IntrospectionEndpoint != test.expectedIssuer+"/introspect" {
				t.Error("metadata introspection_endpoint did not match")
			}

			if metadata.RevocationEndpoint != test.expectedIssuer+"/revoke" {
				t.Error("metadata revocation_endpoint did not match")
			}

			if metadata.ServiceDocumentation != "https://stopnik.webish.dev" {
				t.Error("metadata service_documentation did not match")
			}
		})
	}
}

func Test_MetadataNotAllowedHttpMethods(t *testing.T) {
	var testInvalidMetadataHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidMetadataHttpMethods {
		testMessage := fmt.Sprintf("Metadata with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			initializeConfig(t, "")
			metadataHandler := NewMetadataHandler()

			rr := httptest.NewRecorder()

			metadataHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Metadata, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testMetadataParse(t *testing.T, r *http.Response) response {
	responseBody, bodyReadErr := io.ReadAll(r.Body)

	if bodyReadErr != nil {
		t.Errorf("could not read response body: %v", bodyReadErr)
	}

	if responseBody == nil {
		t.Errorf("response body was nil")
	}

	metadataResponse := response{}
	jsonParseError := json.Unmarshal(responseBody, &metadataResponse)
	if jsonParseError != nil {
		t.Errorf("could not parse response body: %v", jsonParseError)
	}

	return metadataResponse
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
