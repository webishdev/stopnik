package handler

import (
	"net/http"
	"net/http/httptest"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/store"
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
}

func createTestConfig(t *testing.T) *config.Config {
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

	return testConfig
}
