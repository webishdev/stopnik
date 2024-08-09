package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"stopnik/internal/config"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"testing"
)

func Test_Token(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:        "foo",
				Secret:    "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects: []string{"https://example.com/callback"},
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
			},
		},
	}

	err := testConfig.Setup()
	if err != nil {
		t.Error(err)
	}

	testTokenMissingClientCredentials(t, testConfig)

	testTokenMissingGrandType(t, testConfig)

	testTokenNotAllowedHttpMethods(t)
}

func testTokenMissingClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		tokenHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/token", nil))

		if rr.Code != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusForbidden)
		}
	})
}

func testTokenMissingGrandType(t *testing.T, testConfig *config.Config) {
	t.Run("Missing grant type", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/token", nil)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", createBasicAuth("foo", "bar")))

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusForbidden)
		}
	})
}

func testTokenNotAllowedHttpMethods(t *testing.T) {
	var testInvalidTokenHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidTokenHttpMethods {
		testMessage := fmt.Sprintf("Token with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			tokenHandler := CreateTokenHandler(&validation.RequestValidator{}, &store.SessionManager{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			tokenHandler.ServeHTTP(rr, httptest.NewRequest(method, "/token", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func createBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
