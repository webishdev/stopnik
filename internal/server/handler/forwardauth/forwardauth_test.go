package forwardauth

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_ForwardAuth(t *testing.T) {
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

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	testForwardAuthWithoutCookie(t, testConfig)

	testForwardAuthMissingHeaders(t, testConfig)

	testForwardAuthInvalidHeaders(t, testConfig)
}

func testForwardAuthWithoutCookie(t *testing.T, testConfig *config.Config) {
	t.Run("ForwardAuth without cookie", func(t *testing.T) {
		cookieManager := cookie.GetCookieManagerInstance()
		authSessionManager := session.GetAuthSessionManagerInstance()
		forwardSessionManager := session.GetForwardSessionManagerInstance()
		templateManager := template.GetTemplateManagerInstance()

		forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, templateManager)

		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)
		request.Header.Set(internalHttp.XForwardProtocol, "http")
		request.Header.Set(internalHttp.XForwardHost, "localhost:8080")
		request.Header.Set(internalHttp.XForwardUri, "/blabla")

		forwardAuthHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusTemporaryRedirect)
		}

		_, locationError := rr.Result().Location()
		if locationError != nil {
			t.Errorf("location was not provied: %v", locationError)
		}
	})

}

func testForwardAuthMissingHeaders(t *testing.T, testConfig *config.Config) {
	t.Run("ForwardAuth without forward headers", func(t *testing.T) {
		cookieManager := cookie.GetCookieManagerInstance()
		authSessionManager := session.GetAuthSessionManagerInstance()
		forwardSessionManager := session.GetForwardSessionManagerInstance()
		templateManager := template.GetTemplateManagerInstance()

		forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, templateManager)

		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)

		forwardAuthHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testForwardAuthInvalidHeaders(t *testing.T, testConfig *config.Config) {
	t.Run("ForwardAuth with invalid forward headers", func(t *testing.T) {
		cookieManager := cookie.GetCookieManagerInstance()
		authSessionManager := session.GetAuthSessionManagerInstance()
		forwardSessionManager := session.GetForwardSessionManagerInstance()
		templateManager := template.GetTemplateManagerInstance()

		forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, templateManager)

		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)
		request.Header.Set(internalHttp.XForwardProtocol, "!6721abc")
		request.Header.Set(internalHttp.XForwardHost, "??+-#127fkhas:8080")
		request.Header.Set(internalHttp.XForwardUri, "+ß128lj")

		forwardAuthHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusInternalServerError)
		}
	})
}
