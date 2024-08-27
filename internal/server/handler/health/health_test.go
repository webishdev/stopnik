package health

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Health(t *testing.T) {
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
	setupError := testConfig.Setup()
	if setupError != nil {
		t.Fatal(setupError)
	}

	keyManger, keyLoadingError := manager.NewKeyManger(testConfig)
	if keyLoadingError != nil {
		t.Error(keyLoadingError)
		return
	}

	t.Run("Health without token", func(t *testing.T) {
		tokenManager := manager.NewTokenManager(testConfig, manager.NewDefaultKeyLoader(testConfig, keyManger))

		healthHandler := NewHealthHandler(tokenManager)

		httpRequest := &http.Request{
			Method: http.MethodGet,
		}
		rr := httptest.NewRecorder()

		healthHandler.ServeHTTP(rr, httpRequest)

		contentType := rr.Header().Get(internalHttp.ContentType)

		if contentType != internalHttp.ContentTypeJSON {
			t.Errorf("content type should be %s", internalHttp.ContentTypeJSON)
		}

		jsonString := rr.Body.String()

		if jsonString != `{"ping":"pong"}` {
			t.Errorf("json string should be %s, but was %s", `{"ping":"pong"}`, jsonString)
		}

	})

	t.Run("Health with token", func(t *testing.T) {
		tokenManager := manager.NewTokenManager(testConfig, manager.NewDefaultKeyLoader(testConfig, keyManger))

		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Error("client should exist")
		}

		tokenResponse := tokenManager.CreateAccessTokenResponse("foo", client, []string{"a:foo", "b:bar"})

		healthHandler := NewHealthHandler(tokenManager)

		httpRequest := &http.Request{
			Method: http.MethodGet,
			Header: http.Header{
				internalHttp.Authorization: []string{"Bearer " + tokenResponse.AccessTokenKey},
			},
		}
		rr := httptest.NewRecorder()

		healthHandler.ServeHTTP(rr, httpRequest)

		contentType := rr.Header().Get(internalHttp.ContentType)

		if contentType != internalHttp.ContentTypeJSON {
			t.Errorf("content type should be %s", internalHttp.ContentTypeJSON)
		}

		jsonString := rr.Body.String()

		if jsonString != `{"ping":"pong","username":"foo","scopes":["a:foo","b:bar"]}` {
			t.Errorf("json string should be %s, but was %s", `{"ping":"pong","username":"foo","scopes":["a:foo","b:bar"]}`, jsonString)
		}

	})

	var testInvalidHealthHttpMethods = []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidHealthHttpMethods {
		testMessage := fmt.Sprintf("Health with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			healthHandler := NewHealthHandler(&manager.TokenManager{})

			rr := httptest.NewRecorder()

			healthHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Health, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
