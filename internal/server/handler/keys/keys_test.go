package keys

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"github.com/webishdev/stopnik/internal/manager/key"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

type responseKeys struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
}

type response struct {
	Keys []responseKeys `json:"keys"`
}

var keysTestConfig *config.Config

// initializeKeysTestConfig initializes the configuration once, as the key manager keeps the configuration it was created with.
func initializeKeysTestConfig(t *testing.T) *config.Config {
	t.Helper()
	if keysTestConfig != nil {
		return keysTestConfig
	}
	testConfigEntries := config.Entries{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				PrivateKey:   "../../../../.test_files/ecdsa256key.pem",
			},
			{
				Id:           "bar",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				PrivateKey:   "../../../../.test_files/rsa256key.pem",
			},
			{
				Id:           "moo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				PrivateKey:   "../../../../.test_files/ecdsa521key.pem",
			},
		},
	}
	testConfig := &config.Config{
		Server: config.Server{
			PrivateKey: "../../../../.test_files/rsa256key.pem",
		},
	}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
	}
	keysTestConfig = testConfig
	return testConfig
}

func Test_Keys(t *testing.T) {
	initializeKeysTestConfig(t)

	keyManger := key.GetKeyMangerInstance()

	keysHandler := NewKeysHandler(keyManger)

	rr := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, endpoint.Keys, nil)

	keysHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	requestResponse := rr.Result()

	keys := testKeyParse(t, requestResponse)

	if len(keys.Keys) != 3 {
		t.Errorf("handler returned wrong number of keys: got %v want %v", len(keys.Keys), 3)
	}

	containsES512 := slices.ContainsFunc(keys.Keys, func(r responseKeys) bool {
		return r.Alg == jwa.ES512().String() && r.Kty == "EC"
	})

	if !containsES512 {
		t.Error("key for ES512 was missing")
	}

	containsES256 := slices.ContainsFunc(keys.Keys, func(r responseKeys) bool {
		return r.Alg == jwa.ES256().String() && r.Kty == "EC"
	})

	if !containsES256 {
		t.Error("key for ES256 was missing")
	}

	containsRSA256 := slices.ContainsFunc(keys.Keys, func(r responseKeys) bool {
		return r.Alg == jwa.RS256().String() && r.Kty == "RSA"
	})

	if !containsRSA256 {
		t.Error("key for RS256 was missing")
	}
}

func Test_KeysFollowDynamicConfiguration(t *testing.T) {
	testConfig := initializeKeysTestConfig(t)

	keysHandler := NewKeysHandler(key.GetKeyMangerInstance())
	keysHandler.config = testConfig

	requestKeys := func() response {
		rr := httptest.NewRecorder()
		keysHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, endpoint.Keys, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}
		return testKeyParse(t, rr.Result())
	}

	containsAlgorithm := func(keys response, algorithm string) bool {
		return slices.ContainsFunc(keys.Keys, func(r responseKeys) bool {
			return r.Alg == algorithm
		})
	}

	initialKeys := requestKeys()
	if containsAlgorithm(initialKeys, jwa.ES384().String()) {
		t.Fatal("ES384 key should not exist before the client was added")
	}

	applyError := testConfig.ApplyEntries(config.Entries{
		Clients: []config.Client{
			{
				Id:         "new",
				Redirects:  []string{"https://example.com/callback"},
				PrivateKey: "../../../../.test_files/ecdsa384key.pem",
			},
		},
	})
	if applyError != nil {
		t.Fatal(applyError)
	}

	updatedKeys := requestKeys()
	if !containsAlgorithm(updatedKeys, jwa.ES384().String()) {
		t.Error("key of the added client should be served after the dynamic configuration changed")
	}

	newKid := ""
	for _, currentKey := range updatedKeys.Keys {
		if currentKey.Alg == jwa.ES384().String() {
			newKid = currentKey.Kid
		}
	}
	if newKid == "" || slices.ContainsFunc(initialKeys.Keys, func(r responseKeys) bool { return r.Kid == newKid }) {
		t.Errorf("expected a new kid, got %q", newKid)
	}
}

func Test_KeysNotAllowedHttpMethods(t *testing.T) {
	var testInvalidIntrospectHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidIntrospectHttpMethods {
		testMessage := fmt.Sprintf("Keys with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			keyManger := key.GetKeyMangerInstance()

			keysHandler := NewKeysHandler(keyManger)

			rr := httptest.NewRecorder()

			keysHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Keys, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testKeyParse(t *testing.T, r *http.Response) response {
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
