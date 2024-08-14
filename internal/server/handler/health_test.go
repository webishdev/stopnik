package handler

import (
	"fmt"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Health(t *testing.T) {
	t.Run("Health without token", func(t *testing.T) {
		testConfig := createTestConfig(t)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

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
		testConfig := createTestConfig(t)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

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
			healthHandler := NewHealthHandler(&store.TokenManager{})

			rr := httptest.NewRecorder()

			healthHandler.ServeHTTP(rr, httptest.NewRequest(method, "/health", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
