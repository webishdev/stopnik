package oidc

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/server/handler/keys"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func Test_OidcConfiguration(t *testing.T) {
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
		testMessage := fmt.Sprintf("OIDC configuration with base path '%s' and issuer '%s'", test.basePath, test.issuer)
		t.Run(testMessage, func(t *testing.T) {
			initializeConfig(t, test.basePath, test.issuer)
			oidcDiscoveryHandler := NewOidcDiscoveryHandler(key.GetKeyMangerInstance())

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)
			// The Host header can be manipulated by a client and must not be used
			request.Host = "evil.example"

			oidcDiscoveryHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			if strings.Contains(rr.Body.String(), "evil.example") {
				t.Errorf("response contains a value derived from the Host header: %s", rr.Body.String())
			}

			requestResponse := rr.Result()

			oidcConfigurationParse := testOidcConfigurationParse(t, requestResponse)

			if oidcConfigurationParse.Issuer != test.expectedIssuer {
				t.Error("oidcConfigurationParse issuer did not match")
			}

			if oidcConfigurationParse.AuthorizationEndpoint != test.expectedBaseURL+"/authorize" {
				t.Error("oidcConfigurationParse authorization_endpoint did not match")
			}

			if oidcConfigurationParse.TokenEndpoint != test.expectedBaseURL+"/token" {
				t.Error("oidcConfigurationParse token_endpoint did not match")
			}

			if oidcConfigurationParse.JWKsUri != test.expectedBaseURL+"/keys" {
				t.Error("oidcConfigurationParse jwks_uri did not match")
			}

			if oidcConfigurationParse.IntrospectionEndpoint != test.expectedBaseURL+"/introspect" {
				t.Error("oidcConfigurationParse introspection_endpoint did not match")
			}

			if oidcConfigurationParse.RevocationEndpoint != test.expectedBaseURL+"/revoke" {
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
			initializeConfig(t, "", "https://auth.example.com")
			oidcDiscoveryHandler := NewOidcDiscoveryHandler(key.GetKeyMangerInstance())

			rr := httptest.NewRecorder()

			oidcDiscoveryHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Metadata, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func Test_OidcConfigurationSupportedGrantAndResponseTypes(t *testing.T) {
	initializeConfig(t, "", "https://auth.example.com")
	oidcDiscoveryHandler := NewOidcDiscoveryHandler(key.GetKeyMangerInstance())

	rr := httptest.NewRecorder()

	oidcDiscoveryHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, endpoint.OidcDiscovery, nil))

	oidcConfiguration := testOidcConfigurationParse(t, rr.Result())

	expectedGrantTypes := []oauth2.GrantType{oauth2.GtAuthorizationCode, oauth2.GtRefreshToken}
	if !reflect.DeepEqual(oidcConfiguration.GrantTypesSupported, expectedGrantTypes) {
		t.Errorf("grant_types_supported %v did not match %v", oidcConfiguration.GrantTypesSupported, expectedGrantTypes)
	}

	expectedResponseTypes := []oauth2.ResponseType{oauth2.RtCode}
	if !reflect.DeepEqual(oidcConfiguration.ResponseTypesSupported, expectedResponseTypes) {
		t.Errorf("response_types_supported %v did not match %v", oidcConfiguration.ResponseTypesSupported, expectedResponseTypes)
	}
}

func Test_OidcConfigurationSigningAlgorithmsMatchKeys(t *testing.T) {
	initializeConfig(t, "", "https://auth.example.com")
	keyManager := key.GetKeyMangerInstance()
	oidcDiscoveryHandler := NewOidcDiscoveryHandler(keyManager)
	keysHandler := keys.NewKeysHandler(keyManager)

	discoveryRecorder := httptest.NewRecorder()
	oidcDiscoveryHandler.ServeHTTP(discoveryRecorder, httptest.NewRequest(http.MethodGet, endpoint.OidcDiscovery, nil))
	oidcConfiguration := testOidcConfigurationParse(t, discoveryRecorder.Result())

	keysRecorder := httptest.NewRecorder()
	keysHandler.ServeHTTP(keysRecorder, httptest.NewRequest(http.MethodGet, endpoint.Keys, nil))
	keySet := struct {
		Keys []struct {
			Alg string `json:"alg"`
		} `json:"keys"`
	}{}
	if jsonError := json.Unmarshal(keysRecorder.Body.Bytes(), &keySet); jsonError != nil {
		t.Fatal(jsonError)
	}

	var keyAlgorithms []string
	for _, currentKey := range keySet.Keys {
		if !slices.Contains(keyAlgorithms, currentKey.Alg) {
			keyAlgorithms = append(keyAlgorithms, currentKey.Alg)
		}
	}
	var advertisedAlgorithms []string
	for _, algorithm := range oidcConfiguration.IdTokenSigningAlgValuesSupported {
		advertisedAlgorithms = append(advertisedAlgorithms, algorithm.String())
	}
	slices.Sort(keyAlgorithms)
	slices.Sort(advertisedAlgorithms)

	if len(keyAlgorithms) == 0 || !reflect.DeepEqual(keyAlgorithms, advertisedAlgorithms) {
		t.Errorf("advertised algorithms %v did not match the algorithms of the keys %v", advertisedAlgorithms, keyAlgorithms)
	}
	if slices.Contains(advertisedAlgorithms, "HS256") {
		t.Error("HS256 must not be advertised")
	}
	if strings.Contains(discoveryRecorder.Body.String(), "endpoint_auth_signing_alg_values_supported") {
		t.Error("JWT client authentication is not supported and must not be advertised")
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

func initializeConfig(t *testing.T, basePath string, issuer string) {
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
	applyError := testConfig.ApplyEntries(config.Entries{
		Clients: []config.Client{
			{
				Id:        "foo",
				Oidc:      true,
				Redirects: []string{"https://example.com/callback"},
			},
		},
	})
	if applyError != nil {
		t.Fatal(applyError)
	}
}
