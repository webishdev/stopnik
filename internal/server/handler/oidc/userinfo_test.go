package oidc

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	"github.com/webishdev/stopnik/internal/manager"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_UserInfo(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
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

	keyManger, keyLoadingError := manager.NewKeyManger(testConfig)
	if keyLoadingError != nil {
		t.Error(keyLoadingError)
	}

	testOidcUserInfoNotAllowedHttpMethods(t, testConfig, keyManger)
}

func testOidcUserInfoNotAllowedHttpMethods(t *testing.T, testConfig *config.Config, keyManger *manager.KeyManger) {
	var testInvalidOidcUserInfoHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidOidcUserInfoHttpMethods {
		testMessage := fmt.Sprintf("OIDC configuration with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			tokenManager := manager.NewTokenManager(testConfig, manager.NewDefaultKeyLoader(testConfig, keyManger))
			oidcDiscoveryHandler := NewOidcUserInfoHandler(tokenManager)

			rr := httptest.NewRecorder()

			oidcDiscoveryHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Metadata, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
