package forwardauth

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"uuid"
)

func Test_ForwardAuthWithoutCookie(t *testing.T) {
	testConfig := createTestConfig(t)
	cookieManager := cookie.GetCookieManagerInstance()
	authSessionManager := session.GetAuthSessionManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, loginSessionManager, templateManager)

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
}

func Test_ForwardAuthWithCookie(t *testing.T) {
	testConfig := createTestConfig(t)
	cookieManager := cookie.GetCookieManagerInstance()
	authSessionManager := session.GetAuthSessionManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	user, _ := testConfig.GetUser("foo")
	loginSession := &session.LoginSession{
		Id:       uuid.New().String(),
		Username: user.Username,
	}
	loginSessionManager.StartSession(loginSession)
	authCookie, _ := cookieManager.CreateForwardAuthCookie(user.Username, loginSession.Id)

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, loginSessionManager, templateManager)

	rr := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)
	request.Header.Set(internalHttp.XForwardProtocol, "http")
	request.Header.Set(internalHttp.XForwardHost, "localhost:8080")
	request.Header.Set(internalHttp.XForwardUri, "/blabla")
	request.AddCookie(&authCookie)

	forwardAuthHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusTemporaryRedirect)
	}

	_, locationError := rr.Result().Location()
	if locationError == nil {
		t.Errorf("location was provied")
	}
}

func Test_ForwardAuthMissingHeaders(t *testing.T) {
	testConfig := createTestConfig(t)
	cookieManager := cookie.GetCookieManagerInstance()
	authSessionManager := session.GetAuthSessionManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, loginSessionManager, templateManager)

	rr := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)

	forwardAuthHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_ForwardAuthInvalidHeaders(t *testing.T) {
	testConfig := createTestConfig(t)
	cookieManager := cookie.GetCookieManagerInstance()
	authSessionManager := session.GetAuthSessionManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, loginSessionManager, templateManager)

	rr := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)
	request.Header.Set(internalHttp.XForwardProtocol, "!6721abc")
	request.Header.Set(internalHttp.XForwardHost, "??+-#127fkhas:8080")
	request.Header.Set(internalHttp.XForwardUri, "+ß128lj")

	forwardAuthHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusInternalServerError)
	}
}

func Test_ForwardAuthCodeUsage(t *testing.T) {
	type codeUsageParameter struct {
		name         string
		username     string
		otherClient  bool
		expectedCode int
	}

	var codeUsageParameters = []codeUsageParameter{
		{"Valid code", "foo", false, http.StatusTemporaryRedirect},
		{"User not logged in", "", false, http.StatusBadRequest},
		{"Code issued for other client", "foo", true, http.StatusBadRequest},
	}

	for _, test := range codeUsageParameters {
		t.Run(test.name, func(t *testing.T) {
			testConfig := createTestConfig(t)
			forwardAuthClient, _ := testConfig.GetForwardAuthClient()
			cookieManager := cookie.GetCookieManagerInstance()
			authSessionManager := session.GetAuthSessionManagerInstance()
			forwardSessionManager := session.GetForwardSessionManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			templateManager := template.GetTemplateManagerInstance()

			codeVerifier := uuid.New().String()
			clientId := forwardAuthClient.Id
			if test.otherClient {
				clientId = "foo"
			}
			authSession := &session.AuthSession{
				Id:                  uuid.New().String(),
				ClientId:            clientId,
				Username:            test.username,
				CodeChallenge:       codeVerifier,
				CodeChallengeMethod: string(pkce.S256),
			}
			authSessionManager.StartSession(authSession)
			forwardSession := &session.ForwardSession{
				Id:                    uuid.New().String(),
				CodeChallengeVerifier: pkce.CalculatePKCE(pkce.S256, codeVerifier),
				RedirectUri:           "http://localhost:8080/blabla",
				State:                 "xyz",
			}
			forwardSessionManager.StartSession(forwardSession)

			forwardAuthHandler := NewForwardAuthHandler(cookieManager, authSessionManager, forwardSessionManager, loginSessionManager, templateManager)

			forwardUri := fmt.Sprintf("/blabla?%s=%s&%s=%s&%s=%s", oauth2.ParameterCode, authSession.Id, oauth2.ParameterState, forwardSession.State, testConfig.GetForwardAuthParameterName(), forwardSession.Id)
			createRequest := func() *http.Request {
				request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)
				request.Header.Set(internalHttp.XForwardProtocol, "http")
				request.Header.Set(internalHttp.XForwardHost, "localhost:8080")
				request.Header.Set(internalHttp.XForwardUri, forwardUri)
				return request
			}

			rr := httptest.NewRecorder()
			forwardAuthHandler.ServeHTTP(rr, createRequest())

			if rr.Code != test.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, test.expectedCode)
			}

			// A code can only be used once
			replay := httptest.NewRecorder()
			forwardAuthHandler.ServeHTTP(replay, createRequest())

			if replay.Code != http.StatusBadRequest {
				t.Errorf("replay returned wrong status code: got %v want %v", replay.Code, http.StatusBadRequest)
			}
		})
	}
}

func createTestConfig(t *testing.T) *config.Config {
	testConfig := &config.Config{
		Server: config.Server{
			ForwardAuth: config.ForwardAuth{
				Enabled:     true,
				ExternalUrl: "http://foo.com",
			},
		},
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
	return testConfig
}
