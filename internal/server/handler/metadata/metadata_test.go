package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/endpoint"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Metadata(t *testing.T) {
	testMetadata(t)
	testMetadataNotAllowedHttpMethods(t)
}

func testMetadata(t *testing.T) {
	t.Run("Get metadata", func(t *testing.T) {
		metadataHandler := NewMetadataHandler()

		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)

		metadataHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		requestResponse := rr.Result()

		metadata := testMetadataParse(t, requestResponse)

		if metadata.Issuer != "http://example.com" {
			t.Error("metadata issuer did not match")
		}

		if metadata.AuthorizationEndpoint != "http://example.com/authorize" {
			t.Error("metadata authorization_endpoint did not match")
		}

		if metadata.TokenEndpoint != "http://example.com/token" {
			t.Error("metadata token_endpoint did not match")
		}

		if metadata.JWKsUri != "http://example.com/keys" {
			t.Error("metadata jwks_uri did not match")
		}

		if metadata.IntrospectionEndpoint != "http://example.com/introspect" {
			t.Error("metadata introspection_endpoint did not match")
		}

		if metadata.RevocationEndpoint != "http://example.com/revoke" {
			t.Error("metadata revocation_endpoint did not match")
		}

		if metadata.ServiceDocumentation != "https://stopnik.webish.dev" {
			t.Error("metadata service_documentation did not match")
		}
	})
}

func testMetadataNotAllowedHttpMethods(t *testing.T) {
	var testInvalidMetadataHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidMetadataHttpMethods {
		testMessage := fmt.Sprintf("Metadata with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
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

	keysResponse := response{}
	jsonParseError := json.Unmarshal(responseBody, &keysResponse)
	if jsonParseError != nil {
		t.Errorf("could not parse response body: %v", jsonParseError)
	}

	return keysResponse
}
