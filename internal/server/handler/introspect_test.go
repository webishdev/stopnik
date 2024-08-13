package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"stopnik/internal/config"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"testing"
)

func Test_Introspect(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:         "foo",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				RefreshTTL: 100,
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

	testIntrospectNotAllowedHttpMethods(t)

	testIntrospectMissingClientCredentials(t, testConfig)

	testIntrospectInvalidClientCredentials(t, testConfig)
}

func testIntrospectMissingClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		// sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

		rr := httptest.NewRecorder()

		introspectHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/introspect", nil))

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func testIntrospectInvalidClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Invalid client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		//sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/introspect", nil)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "xxx")))

		introspectHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func testIntrospectNotAllowedHttpMethods(t *testing.T) {
	var testInvalidIntrospectHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidIntrospectHttpMethods {
		testMessage := fmt.Sprintf("Introspect with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			introspectHandler := CreateIntrospectHandler(&config.Config{}, &validation.RequestValidator{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			introspectHandler.ServeHTTP(rr, httptest.NewRequest(method, "/introspect", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
