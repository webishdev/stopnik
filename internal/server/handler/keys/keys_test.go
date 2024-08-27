package keys

import (
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"github.com/webishdev/stopnik/internal/manager"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type responseKeys struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type response struct {
	Keys []responseKeys `json:"keys"`
}

func Test_Keys(t *testing.T) {
	testConfig := &config.Config{
		Server: config.Server{
			PrivateKey: "../../../../test_keys/rsa256key.pem",
		},
		Clients: []config.Client{
			{
				Id:         "foo",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				PrivateKey: "../../../../test_keys/ecdsa256key.pem",
			},
			{
				Id:         "bar",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				PrivateKey: "../../../../test_keys/rsa256key.pem",
			},
			{
				Id:         "moo",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				PrivateKey: "../../../../test_keys/ecdsa521key.pem",
			},
		},
	}

	err := testConfig.Setup()
	if err != nil {
		t.Error(err)
	}

	testKeys(t, testConfig)

	testKeysNotAllowedHttpMethods(t, testConfig)

}

func testKeys(t *testing.T, testConfig *config.Config) {
	t.Run("Get keys", func(t *testing.T) {
		keyManger, keyManagerError := manager.NewKeyManger(testConfig)
		if keyManagerError != nil {
			t.Error(keyManagerError)
		}
		keysHandler := NewKeysHandler(keyManger, testConfig)

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
	})
}

func testKeysNotAllowedHttpMethods(t *testing.T, testConfig *config.Config) {
	var testInvalidIntrospectHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidIntrospectHttpMethods {
		testMessage := fmt.Sprintf("Introspect with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			keyManger, keyManagerError := manager.NewKeyManger(testConfig)
			if keyManagerError != nil {
				t.Error(keyManagerError)
			}
			keysHandler := NewKeysHandler(keyManger, testConfig)

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
