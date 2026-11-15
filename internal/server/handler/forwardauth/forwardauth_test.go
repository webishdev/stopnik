package forwardauth

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/handler/authorize"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"uuid"
)

func Test_ForwardAuthWithoutCookie(t *testing.T) {
	testConfig := createTestConfig(t)
	cookieManager := cookie.GetCookieManagerInstance()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authorizationCodeManager, forwardSessionManager, loginSessionManager, templateManager)

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
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
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

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authorizationCodeManager, forwardSessionManager, loginSessionManager, templateManager)

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
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authorizationCodeManager, forwardSessionManager, loginSessionManager, templateManager)

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
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authorizationCodeManager, forwardSessionManager, loginSessionManager, templateManager)

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
			authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
			forwardSessionManager := session.GetForwardSessionManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			templateManager := template.GetTemplateManagerInstance()

			codeVerifier := pkce.GenerateCodeVerifier()
			clientId := forwardAuthClient.Id
			if test.otherClient {
				clientId = "foo"
			}
			authorizationCode := &session.AuthorizationCode{
				Code:                session.GenerateAuthorizationCode(),
				ClientId:            clientId,
				Username:            test.username,
				CodeChallenge:       pkce.CalculatePKCE(pkce.S256, codeVerifier),
				CodeChallengeMethod: string(pkce.S256),
			}
			authorizationCodeManager.StartSession(authorizationCode)
			forwardSession := &session.ForwardSession{
				Id:                    uuid.New().String(),
				CodeChallengeVerifier: codeVerifier,
				RedirectUri:           "http://localhost:8080/blabla",
				State:                 "xyz",
			}
			forwardSessionManager.StartSession(forwardSession)

			forwardAuthHandler := NewForwardAuthHandler(cookieManager, authorizationCodeManager, forwardSessionManager, loginSessionManager, templateManager)

			forwardUri := fmt.Sprintf("/blabla?%s=%s&%s=%s&%s=%s", oauth2.ParameterCode, authorizationCode.Code, oauth2.ParameterState, forwardSession.State, testConfig.GetForwardAuthParameterName(), forwardSession.Id)
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

func Test_ForwardAuthEndToEnd(t *testing.T) {
	testConfig := createTestConfig(t)
	cookieManager := cookie.GetCookieManagerInstance()
	authSessionManager := session.GetAuthSessionManagerInstance()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	forwardSessionManager := session.GetForwardSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	templateManager := template.GetTemplateManagerInstance()
	tokenManager := token.GetTokenManagerInstance()
	requestValidator := validation.NewRequestValidator()

	forwardAuthHandler := NewForwardAuthHandler(cookieManager, authorizationCodeManager, forwardSessionManager, loginSessionManager, templateManager)
	authorizeHandler := authorize.NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, authorizationCodeManager, loginSessionManager, tokenManager, templateManager)

	createForwardRequest := func(forwardUri string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, testConfig.GetForwardAuthEndpoint(), nil)
		request.Header.Set(internalHttp.XForwardProtocol, "http")
		request.Header.Set(internalHttp.XForwardHost, "localhost:8080")
		request.Header.Set(internalHttp.XForwardUri, forwardUri)
		return request
	}

	// Traefik asks for a request without a cookie, the user is redirected to the authorization endpoint
	forwardRecorder := httptest.NewRecorder()
	forwardAuthHandler.ServeHTTP(forwardRecorder, createForwardRequest("/blabla?foo=bar"))

	if forwardRecorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("handler returned wrong status code: got %v want %v", forwardRecorder.Code, http.StatusTemporaryRedirect)
	}
	authorizeLocation, authorizeLocationError := forwardRecorder.Result().Location()
	if authorizeLocationError != nil {
		t.Fatalf("location was not provided: %v", authorizeLocationError)
	}

	// The user is already logged in at STOPnik, so the code is issued directly
	user, _ := testConfig.GetUser("foo")
	loginSession := &session.LoginSession{
		Id:       uuid.New().String(),
		Username: user.Username,
	}
	loginSessionManager.StartSession(loginSession)
	authCookie, _ := cookieManager.CreateAuthCookie(user.Username, loginSession.Id)

	authorizeRecorder := httptest.NewRecorder()
	authorizeRequest := httptest.NewRequest(http.MethodGet, authorizeLocation.RequestURI(), nil)
	authorizeRequest.AddCookie(&authCookie)
	authorizeHandler.ServeHTTP(authorizeRecorder, authorizeRequest)

	if authorizeRecorder.Code != http.StatusFound {
		t.Fatalf("authorize handler returned wrong status code: got %v want %v", authorizeRecorder.Code, http.StatusFound)
	}
	callbackLocation, callbackLocationError := authorizeRecorder.Result().Location()
	if callbackLocationError != nil {
		t.Fatalf("location was not provided: %v", callbackLocationError)
	}
	if callbackLocation.Query().Get(oauth2.ParameterCode) == "" {
		t.Fatalf("code was not provided, got location %v", callbackLocation)
	}

	// Traefik asks again for the callback, the code is exchanged for the forward auth cookie
	callbackRecorder := httptest.NewRecorder()
	forwardAuthHandler.ServeHTTP(callbackRecorder, createForwardRequest(callbackLocation.RequestURI()))

	if callbackRecorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("handler returned wrong status code: got %v want %v", callbackRecorder.Code, http.StatusTemporaryRedirect)
	}
	if callbackRecorder.Header().Get(internalHttp.Location) != "http://localhost:8080/blabla?foo=bar" {
		t.Errorf("handler redirected to %v, expected the originally requested URL", callbackRecorder.Header().Get(internalHttp.Location))
	}

	var forwardAuthCookie *http.Cookie
	for _, responseCookie := range callbackRecorder.Result().Cookies() {
		if responseCookie.Name == testConfig.GetForwardAuthCookieName() {
			forwardAuthCookie = responseCookie
		}
	}
	if forwardAuthCookie == nil {
		t.Fatal("forward auth cookie was not set")
	}

	// With the cookie the request is allowed
	allowedRecorder := httptest.NewRecorder()
	allowedRequest := createForwardRequest("/blabla?foo=bar")
	allowedRequest.AddCookie(forwardAuthCookie)
	forwardAuthHandler.ServeHTTP(allowedRecorder, allowedRequest)

	if allowedRecorder.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", allowedRecorder.Code, http.StatusOK)
	}
}

func createTestConfig(t *testing.T) *config.Config {
	testConfigEntries := config.Entries{
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
	testConfig := &config.Config{
		Server: config.Server{
			ForwardAuth: config.ForwardAuth{
				Enabled:     true,
				ExternalUrl: "http://foo.com",
				Redirects:   []string{"http://localhost:8080/*"},
			},
		},
	}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
	}
	return testConfig
}
