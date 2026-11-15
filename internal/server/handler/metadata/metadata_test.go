package metadata

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"github.com/webishdev/stopnik/internal/oauth2"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func Test_Metadata(t *testing.T) {
	type basePathParameter struct {
		basePath        string
		issuer          string
		expectedIssuer  string
		expectedBaseURL string
	}

	var basePathParameters = []basePathParameter{
		{basePath: "", issuer: "https://auth.example.com", expectedIssuer: "https://auth.example.com", expectedBaseURL: "https://auth.example.com"},
		{basePath: "/", issuer: "https://auth.example.com", expectedIssuer: "https://auth.example.com", expectedBaseURL: "https://auth.example.com"},
		{basePath: "/auth", issuer: "https://example.com/auth", expectedIssuer: "https://example.com/auth", expectedBaseURL: "https://example.com/auth"},
		{basePath: "auth/", issuer: "https://example.com/auth", expectedIssuer: "https://example.com/auth", expectedBaseURL: "https://example.com/auth"},
		{basePath: "/auth", issuer: "https://issuer.example.com", expectedIssuer: "https://issuer.example.com", expectedBaseURL: "https://issuer.example.com/auth"},
	}

	for _, test := range basePathParameters {
		testMessage := fmt.Sprintf("Metadata with base path '%s' and issuer '%s'", test.basePath, test.issuer)
		t.Run(testMessage, func(t *testing.T) {
			initializeConfig(t, test.basePath, test.issuer)
			metadataHandler := NewMetadataHandler()

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)
			// The Host header can be manipulated by a client and must not be used
			request.Host = "evil.example"

			metadataHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			if strings.Contains(rr.Body.String(), "evil.example") {
				t.Errorf("response contains a value derived from the Host header: %s", rr.Body.String())
			}

			requestResponse := rr.Result()

			metadata := testMetadataParse(t, requestResponse)

			if metadata.Issuer != test.expectedIssuer {
				t.Error("metadata issuer did not match")
			}

			if metadata.AuthorizationEndpoint != test.expectedBaseURL+"/authorize" {
				t.Error("metadata authorization_endpoint did not match")
			}

			if metadata.TokenEndpoint != test.expectedBaseURL+"/token" {
				t.Error("metadata token_endpoint did not match")
			}

			if metadata.JWKsUri != test.expectedBaseURL+"/keys" {
				t.Error("metadata jwks_uri did not match")
			}

			if metadata.IntrospectionEndpoint != test.expectedBaseURL+"/introspect" {
				t.Error("metadata introspection_endpoint did not match")
			}

			if metadata.RevocationEndpoint != test.expectedBaseURL+"/revoke" {
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
			initializeConfig(t, "", "https://auth.example.com")
			metadataHandler := NewMetadataHandler()

			rr := httptest.NewRecorder()

			metadataHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Metadata, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func Test_MetadataSupportedGrantAndResponseTypes(t *testing.T) {
	testConfig := initializeConfig(t, "", "https://auth.example.com")
	applyError := testConfig.ApplyEntries(config.Entries{
		Clients: []config.Client{
			{Id: "foo", Redirects: []string{"https://example.com/callback"}},
			{Id: "bar", Redirects: []string{"https://example.com/callback"}, GrantTypes: []string{"implicit"}},
		},
	})
	if applyError != nil {
		t.Fatal(applyError)
	}
	metadataHandler := NewMetadataHandler()

	rr := httptest.NewRecorder()

	metadataHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, endpoint.Metadata, nil))

	metadata := testMetadataParse(t, rr.Result())

	expectedGrantTypes := []oauth2.GrantType{oauth2.GtAuthorizationCode, oauth2.GtRefreshToken, oauth2.GtImplicit}
	if !reflect.DeepEqual(metadata.GrantTypesSupported, expectedGrantTypes) {
		t.Errorf("grant_types_supported %v did not match %v", metadata.GrantTypesSupported, expectedGrantTypes)
	}

	expectedResponseTypes := []oauth2.ResponseType{oauth2.RtCode, oauth2.RtToken}
	if !reflect.DeepEqual(metadata.ResponseTypesSupported, expectedResponseTypes) {
		t.Errorf("response_types_supported %v did not match %v", metadata.ResponseTypesSupported, expectedResponseTypes)
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

func initializeConfig(t *testing.T, basePath string, issuer string) *config.Config {
	testConfig := &config.Config{
		Server: config.Server{
			BasePath: basePath,
			Issuer:   issuer,
		},
	}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	return testConfig
}
