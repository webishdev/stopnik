package authorize

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/cookie"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func Test_AuthorizeInvalidLogin(t *testing.T) {
	createTestConfig(t)
	type invalidLoginParameter struct {
		state string
		scope string
	}

	var invalidLoginParameters = []invalidLoginParameter{
		{"", ""},
		{"abc", ""},
		{"", "foo:moo"},
		{"abc", "foo:moo"},
	}
	for _, test := range invalidLoginParameters {
		testMessage := fmt.Sprintf("Invalid login credentials with with state %v scope %v", test.state, test.scope)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterToken)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
			})
			cookieManager := cookie.GetCookieManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			requestValidator := validation.NewRequestValidator()

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_auth_session", uuid.NewString(),
				"stopnik_username", "foo",
				"stopnik_password", "xxx",
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, parsedUri.String(), body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusSeeOther {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusSeeOther)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			clientIdQueryParameter := location.Query().Get(oauth2.ParameterClientId)

			if clientIdQueryParameter != "foo" {
				t.Errorf("client id query parameter %v did not match expected value: %v", clientIdQueryParameter, "foo")
			}

			redirectUriQueryParameter := location.Query().Get(oauth2.ParameterRedirectUri)

			if redirectUriQueryParameter != "https://example.com/callback" {
				t.Errorf("redirecut uri query parameter %v did not match: %v", redirectUriQueryParameter, "https://example.com/callback")
			}

			responseTypeQueryParameter := location.Query().Get(oauth2.ParameterResponseType)

			if responseTypeQueryParameter != oauth2.ParameterToken {
				t.Errorf("response type query parameter %v did not match: %v", responseTypeQueryParameter, oauth2.ParameterToken)
			}

			stateQueryParameter := location.Query().Get(oauth2.ParameterState)

			if test.state != "" && stateQueryParameter != test.state {
				t.Errorf("state query parameter %v did not match: %v", responseTypeQueryParameter, test.state)
			}

			scopeQueryParameter := location.Query().Get(oauth2.ParameterScope)

			if test.scope != "" && scopeQueryParameter != test.scope {
				t.Errorf("scope query parameter %v did not match: %v", scopeQueryParameter, test.scope)
			}
		})
	}
}

func Test_AuthorizeEmptyLogin(t *testing.T) {
	createTestConfig(t)
	type emptyLoginParameter struct {
		state string
		scope string
	}

	var emptyLoginParameters = []emptyLoginParameter{
		{"", ""},
		{"abc", ""},
		{"", "foo:moo"},
		{"abc", "foo:moo"},
	}
	for _, test := range emptyLoginParameters {
		testMessage := fmt.Sprintf("Empty login credentials with with state %v scope %v", test.state, test.scope)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterToken)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
			})
			cookieManager := cookie.GetCookieManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			requestValidator := validation.NewRequestValidator()

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_auth_session", uuid.NewString(),
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, parsedUri.String(), body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusSeeOther {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusSeeOther)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			clientIdQueryParameter := location.Query().Get(oauth2.ParameterClientId)

			if clientIdQueryParameter != "foo" {
				t.Errorf("client id query parameter %v did not match expected value: %v", clientIdQueryParameter, "foo")
			}

			redirectUriQueryParameter := location.Query().Get(oauth2.ParameterRedirectUri)

			if redirectUriQueryParameter != "https://example.com/callback" {
				t.Errorf("redirecut uri query parameter %v did not match: %v", redirectUriQueryParameter, "https://example.com/callback")
			}

			responseTypeQueryParameter := location.Query().Get(oauth2.ParameterResponseType)

			if responseTypeQueryParameter != oauth2.ParameterToken {
				t.Errorf("response type query parameter %v did not match: %v", responseTypeQueryParameter, oauth2.ParameterToken)
			}

			stateQueryParameter := location.Query().Get(oauth2.ParameterState)

			if test.state != "" && stateQueryParameter != test.state {
				t.Errorf("state query parameter %v did not match: %v", responseTypeQueryParameter, test.state)
			}

			scopeQueryParameter := location.Query().Get(oauth2.ParameterScope)

			if test.scope != "" && scopeQueryParameter != test.scope {
				t.Errorf("scope query parameter %v did not match: %v", scopeQueryParameter, test.scope)
			}
		})
	}
}

func Test_AuthorizeValidLoginNoSession(t *testing.T) {
	createTestConfig(t)
	type validLoginParameter struct {
		state string
		scope string
	}

	var validLoginParameters = []validLoginParameter{
		{"", ""},
		{"abc", ""},
		{"", "foo:moo"},
		{"abc", "foo:moo"},
	}
	for _, test := range validLoginParameters {
		testMessage := fmt.Sprintf("Valid login credentials, no session, with with state %v scope %v", test.state, test.scope)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterToken)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
			})
			requestValidator := validation.NewRequestValidator()
			authSessionManager := session.GetAuthSessionManagerInstance()
			cookieManager := cookie.GetCookieManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			tokenManager := token.GetTokenManagerInstance()

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, tokenManager, &template.Manager{})

			loginToken := requestValidator.NewLoginToken(uuid.NewString())

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_auth_session", loginToken,
				"stopnik_username", "foo",
				"stopnik_password", "bar",
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, parsedUri.String(), body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusSeeOther {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusSeeOther)
			}

			cookies := rr.Result().Cookies()

			if len(cookies) != 0 {
				t.Errorf("cookies returned when it should not have been: %v", cookies)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			clientIdQueryParameter := location.Query().Get(oauth2.ParameterClientId)

			if clientIdQueryParameter != "foo" {
				t.Errorf("client id query parameter %v did not match expected value: %v", clientIdQueryParameter, "foo")
			}

			redirectUriQueryParameter := location.Query().Get(oauth2.ParameterRedirectUri)

			if redirectUriQueryParameter != "https://example.com/callback" {
				t.Errorf("redirecut uri query parameter %v did not match: %v", redirectUriQueryParameter, "https://example.com/callback")
			}

			responseTypeQueryParameter := location.Query().Get(oauth2.ParameterResponseType)

			if responseTypeQueryParameter != oauth2.ParameterToken {
				t.Errorf("response type query parameter %v did not match: %v", responseTypeQueryParameter, oauth2.ParameterToken)
			}

			stateQueryParameter := location.Query().Get(oauth2.ParameterState)

			if test.state != "" && stateQueryParameter != test.state {
				t.Errorf("state query parameter %v did not match: %v", responseTypeQueryParameter, test.state)
			}

			scopeQueryParameter := location.Query().Get(oauth2.ParameterScope)

			if test.scope != "" && scopeQueryParameter != test.scope {
				t.Errorf("scope query parameter %v did not match: %v", scopeQueryParameter, test.scope)
			}
		})
	}
}

func Test_AuthorizeNotAllowedHttpMethods(t *testing.T) {
	var testInvalidAuthorizeHttpMethods = []string{
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidAuthorizeHttpMethods {
		testMessage := fmt.Sprintf("Authorize with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			loginSessionManager := session.GetLoginSessionManagerInstance()

			authorizeHandler := NewAuthorizeHandler(&validation.RequestValidator{}, &cookie.Manager{}, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

			rr := httptest.NewRecorder()

			authorizeHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Authorization, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func Test_AuthorizeNoCookieExists(t *testing.T) {
	createTestConfig(t)
	parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
		query.Set(oauth2.ParameterClientId, "foo")
		query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
		query.Set(oauth2.ParameterResponseType, oauth2.ParameterCode)
	})
	requestValidator := validation.NewRequestValidator()
	authSessionManager := session.GetAuthSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	cookieManager := cookie.GetCookieManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, &token.Manager{}, templateManager)

	rr := httptest.NewRecorder()

	authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get(internalHttp.ContentType)

	if contentType != "text/html; charset=utf-8" {
		t.Errorf("content type was not text/html: %v", contentType)
	}

	response := rr.Result()
	body, bodyReadErr := io.ReadAll(response.Body)

	if bodyReadErr != nil {
		t.Errorf("could not read response body: %v", bodyReadErr)
	}

	if body == nil {
		t.Errorf("response body was nil")
	}
}

func Test_AuthorizeNoCookieExistsPromptNone(t *testing.T) {
	createTestConfig(t)
	parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
		query.Set(oauth2.ParameterClientId, "bar")
		query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
		query.Set(oauth2.ParameterResponseType, oauth2.ParameterCode)
		query.Set(oauth2.ParameterScope, oidc.ScopeOpenId)
		query.Set(oidc.ParameterPrompt, string(oidc.PtNone))
	})
	requestValidator := validation.NewRequestValidator()
	authSessionManager := session.GetAuthSessionManagerInstance()
	loginSessionManager := session.GetLoginSessionManagerInstance()
	cookieManager := cookie.GetCookieManagerInstance()
	templateManager := template.GetTemplateManagerInstance()

	authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, &token.Manager{}, templateManager)

	rr := httptest.NewRecorder()

	authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

	if rr.Code != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
	}

	location, locationError := rr.Result().Location()
	if locationError != nil {
		t.Errorf("location was not provied: %v", locationError)
	}

	errorQueryParameter := location.Query().Get(oauth2.ParameterError)

	errorType, errorTypeExists := oauth2.AuthorizationErrorTypeFromString(errorQueryParameter)

	if !errorTypeExists {
		t.Errorf("error type could not be parsed: %v", errorQueryParameter)
	}

	if errorType != oauth2.AuthorizationEtLoginRequired {
		t.Errorf("error type was not Invalid: %v", errorQueryParameter)
	}

}

func Test_AuthorizeInvalidResponseType(t *testing.T) {
	createTestConfig(t)
	parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
		query.Set(oauth2.ParameterClientId, "foo")
		query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
		query.Set(oauth2.ParameterResponseType, "abc")
	})
	requestValidator := validation.NewRequestValidator()
	loginSessionManager := session.GetLoginSessionManagerInstance()

	authorizeHandler := NewAuthorizeHandler(requestValidator, &cookie.Manager{}, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

	rr := httptest.NewRecorder()

	authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

	if rr.Code != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
	}

	location, locationError := rr.Result().Location()
	if locationError != nil {
		t.Errorf("location was not provied: %v", locationError)
	}

	errorQueryParameter := location.Query().Get(oauth2.ParameterError)

	errorType, errorTypeExists := oauth2.AuthorizationErrorTypeFromString(errorQueryParameter)

	if !errorTypeExists {
		t.Errorf("error type could not be parsed: %v", errorQueryParameter)
	}

	if errorType != oauth2.AuthorizationEtInvalidRequest {
		t.Errorf("error type was not Invalid: %v", errorQueryParameter)
	}
}

func Test_AuthorizeInvalidRedirect(t *testing.T) {
	createTestConfig(t)
	type redirectTest struct {
		redirect string
		status   int
	}

	var redirectTestParameters = []redirectTest{
		{"://hahaNoURI", http.StatusBadRequest},
		{"", http.StatusBadRequest},
		{"http://example.com/foo", http.StatusBadRequest},
	}

	for _, test := range redirectTestParameters {
		testMessage := fmt.Sprintf("Invalid redirect with %s", test.redirect)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, test.redirect)
			})

			loginSessionManager := session.GetLoginSessionManagerInstance()
			requestValidator := validation.NewRequestValidator()

			authorizeHandler := NewAuthorizeHandler(requestValidator, &cookie.Manager{}, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

			rr := httptest.NewRecorder()

			authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

			if rr.Code != test.status {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, test.status)
			}
		})

	}
}

func Test_AuthorizeInvalidClientId(t *testing.T) {
	createTestConfig(t)
	parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
		query.Set(oauth2.ParameterClientId, "bar")
	})

	loginSessionManager := session.GetLoginSessionManagerInstance()
	requestValidator := validation.NewRequestValidator()

	authorizeHandler := NewAuthorizeHandler(requestValidator, &cookie.Manager{}, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

	rr := httptest.NewRecorder()

	authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_AuthorizeNoClientId(t *testing.T) {
	createTestConfig(t)
	loginSessionManager := session.GetLoginSessionManagerInstance()
	requestValidator := validation.NewRequestValidator()

	authorizeHandler := NewAuthorizeHandler(requestValidator, &cookie.Manager{}, &session.AuthManager{}, loginSessionManager, &token.Manager{}, &template.Manager{})

	rr := httptest.NewRecorder()

	authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, endpoint.Authorization, nil))

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_AuthorizeAuthorizationGrant(t *testing.T) {
	testConfig := createTestConfig(t)

	type authorizationGrantParameter struct {
		state                   string
		scope                   string
		pkceCodeChallenge       string
		pkceCodeChallengeMethod *pkce.CodeChallengeMethod
	}

	ccmS256 := pkce.S256
	ccmPlain := pkce.PLAIN

	var authorizationGrantParameters = []authorizationGrantParameter{
		{"", "", "", nil},
		{"abc", "", "", nil},
		{"", "foo:moo", "", nil},
		{"abc", "foo:moo", "", nil},
		{"abc", "foo:moo", uuid.New().String(), &ccmS256},
		{"abc", "foo:moo", uuid.New().String(), &ccmPlain},
	}

	for _, test := range authorizationGrantParameters {
		testMessage := fmt.Sprintf("Cookie exists, authorization code grant with state %v scope %v code challenge %v", test.state, test.scope, test.pkceCodeChallenge)
		t.Run(testMessage, func(t *testing.T) {
			pkceCodeChallenge := ""
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterCode)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
				if test.pkceCodeChallenge != "" && test.pkceCodeChallengeMethod != nil {
					pkceCodeChallenge = pkce.CalculatePKCE(*test.pkceCodeChallengeMethod, test.pkceCodeChallenge)
					query.Set(pkce.ParameterCodeChallenge, pkceCodeChallenge)
				}
			})
			requestValidator := validation.NewRequestValidator()
			authSessionManager := session.GetAuthSessionManagerInstance()
			cookieManager := cookie.GetCookieManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			tokenManager := token.GetTokenManagerInstance()

			user, _ := testConfig.GetUser("foo")
			loginSession := &session.LoginSession{
				Id:       uuid.NewString(),
				Username: user.Username,
			}
			loginSessionManager.StartSession(loginSession)
			authCookie, _ := cookieManager.CreateAuthCookie(user.Username, loginSession.Id)

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, tokenManager, &template.Manager{})

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, parsedUri.String(), nil)
			request.AddCookie(&authCookie)

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			codeQueryParameter := location.Query().Get(oauth2.ParameterCode)

			if codeQueryParameter == "" {
				t.Errorf("code query parameter was not set")
			}

			stateQueryParameter := location.Query().Get(oauth2.ParameterState)

			if stateQueryParameter != test.state {
				t.Errorf("state parameter %v did not match: %v", stateQueryParameter, test.state)
			}

			authSession, sessionExists := authSessionManager.GetSession(codeQueryParameter)
			if !sessionExists {
				t.Errorf("session does not exist: %v", codeQueryParameter)
			}

			if authSession.CodeChallenge != pkceCodeChallenge {
				t.Errorf("session code challenge %v did not match: %v", authSession.CodeChallenge, pkceCodeChallenge)
			}

			if pkceCodeChallenge != "" {
				validatePKCE := pkce.ValidatePKCE(*test.pkceCodeChallengeMethod, pkceCodeChallenge, test.pkceCodeChallenge)
				if !validatePKCE {
					t.Errorf("invalid PKCE code challenge: %v", pkceCodeChallenge)
				}
			}
		})
	}
}

func Test_AuthorizeImplicitGrant(t *testing.T) {
	testConfig := createTestConfig(t)

	type implicitGrantParameter struct {
		state string
		scope string
	}

	var implicitGrantParameters = []implicitGrantParameter{
		{"", ""},
		{"abc", ""},
		{"", "foo:moo"},
		{"abc", "foo:moo"},
	}

	for _, test := range implicitGrantParameters {
		testMessage := fmt.Sprintf("Cookie exists, implicit code grant with state %v scope %v", test.state, test.scope)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterToken)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
			})
			requestValidator := validation.NewRequestValidator()
			authSessionManager := session.GetAuthSessionManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			cookieManager := cookie.GetCookieManagerInstance()
			tokenManager := token.GetTokenManagerInstance()

			client, _ := testConfig.GetClient("foo")
			user, _ := testConfig.GetUser("foo")
			loginSession := &session.LoginSession{
				Id:       uuid.NewString(),
				Username: user.Username,
			}
			loginSessionManager.StartSession(loginSession)
			authCookie, _ := cookieManager.CreateAuthCookie(user.Username, loginSession.Id)

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, tokenManager, &template.Manager{})

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, parsedUri.String(), nil)
			request.AddCookie(&authCookie)

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			accessTokenQueryParameter := location.Query().Get(oauth2.ParameterAccessToken)

			if accessTokenQueryParameter == "" {
				t.Errorf("access token query parameter was not set")
			}

			tokenTypeQueryParameter := location.Query().Get(oauth2.ParameterTokenType)

			if tokenTypeQueryParameter != string(oauth2.TtBearer) {
				t.Errorf("token type parameter %v did not match: %v", tokenTypeQueryParameter, oauth2.TtBearer)
			}

			expiresInTypeQueryParameter := location.Query().Get(oauth2.ParameterExpiresIn)
			expiresIn, expiresParseError := strconv.Atoi(expiresInTypeQueryParameter)
			if expiresParseError != nil {
				t.Errorf("expires query parameter was not parsed: %v", expiresParseError)
			}

			accessTokenDuration := time.Minute * time.Duration(client.GetAccessTTL())
			expectedExpiresIn := int(accessTokenDuration / time.Second)

			if expiresIn != expectedExpiresIn {
				t.Errorf("expires in parameter %v did not match %v", expiresIn, expectedExpiresIn)
			}
		})
	}
}

func Test_AuthorizeValidLoginAuthorizationGrant(t *testing.T) {
	testConfig := createTestConfig(t)

	type validLoginParameter struct {
		state string
		scope string
	}

	var validLoginParameters = []validLoginParameter{
		{"", ""},
		{"abc", ""},
		{"", "foo:moo"},
		{"abc", "foo:moo"},
	}
	for _, test := range validLoginParameters {
		testMessage := fmt.Sprintf("Valid login credentials, authorization grant session, with with state %v scope %v", test.state, test.scope)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterCode)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
			})

			client, _ := testConfig.GetClient("foo")

			id := uuid.NewString()
			authSession := &session.AuthSession{
				Id:                  id,
				Redirect:            "https://example.com/callback",
				AuthURI:             parsedUri.RequestURI(),
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseTypes:       []oauth2.ResponseType{oauth2.RtCode},
				Scopes:              []string{test.scope},
				State:               test.state,
			}

			requestValidator := validation.NewRequestValidator()
			authSessionManager := session.GetAuthSessionManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			cookieManager := cookie.GetCookieManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			authSessionManager.StartSession(authSession)

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, tokenManager, &template.Manager{})

			loginToken := requestValidator.NewLoginToken(id)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_auth_session", loginToken,
				"stopnik_username", "foo",
				"stopnik_password", "bar",
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, parsedUri.String(), body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			codeQueryParameter := location.Query().Get(oauth2.ParameterCode)

			if codeQueryParameter == "" {
				t.Errorf("code query parameter was not set")
			}

			stateQueryParameter := location.Query().Get(oauth2.ParameterState)

			if stateQueryParameter != test.state {
				t.Errorf("state parameter %v did not match: %v", stateQueryParameter, test.state)
			}
		})
	}
}

func Test_AuthorizeValidLoginImplicitGrant(t *testing.T) {
	testConfig := createTestConfig(t)

	type validLoginParameter struct {
		state string
		scope string
	}

	var validLoginParameters = []validLoginParameter{
		{"", ""},
		{"abc", ""},
		{"", "foo:moo"},
		{"abc", "foo:moo"},
	}
	for _, test := range validLoginParameters {
		testMessage := fmt.Sprintf("Valid login credentials, implicit grant session with with state %v scope %v", test.state, test.scope)
		t.Run(testMessage, func(t *testing.T) {
			parsedUri := createUri(t, endpoint.Authorization, func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
				query.Set(oauth2.ParameterResponseType, oauth2.ParameterToken)
				if test.state != "" {
					query.Set(oauth2.ParameterState, test.state)
				}
				if test.scope != "" {
					query.Set(oauth2.ParameterScope, test.scope)
				}
			})

			client, _ := testConfig.GetClient("foo")

			id := uuid.NewString()
			authSession := &session.AuthSession{
				Id:                  id,
				Redirect:            "https://example.com/callback",
				AuthURI:             parsedUri.RequestURI(),
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseTypes:       []oauth2.ResponseType{oauth2.RtToken},
				Scopes:              []string{test.scope},
				State:               test.state,
			}

			requestValidator := validation.NewRequestValidator()
			authSessionManager := session.GetAuthSessionManagerInstance()
			loginSessionManager := session.GetLoginSessionManagerInstance()
			cookieManager := cookie.GetCookieManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			authSessionManager.StartSession(authSession)

			authorizeHandler := NewAuthorizeHandler(requestValidator, cookieManager, authSessionManager, loginSessionManager, tokenManager, &template.Manager{})

			loginToken := requestValidator.NewLoginToken(id)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				"stopnik_auth_session", loginToken,
				"stopnik_username", "foo",
				"stopnik_password", "bar",
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, parsedUri.String(), body)
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			location, locationError := rr.Result().Location()
			if locationError != nil {
				t.Errorf("location was not provied: %v", locationError)
			}

			accessTokenQueryParameter := location.Query().Get(oauth2.ParameterAccessToken)

			if accessTokenQueryParameter == "" {
				t.Errorf("access token query parameter was not set")
			}

			tokenTypeQueryParameter := location.Query().Get(oauth2.ParameterTokenType)

			if tokenTypeQueryParameter != string(oauth2.TtBearer) {
				t.Errorf("token type parameter %v did not match: %v", tokenTypeQueryParameter, oauth2.TtBearer)
			}

			expiresInTypeQueryParameter := location.Query().Get(oauth2.ParameterExpiresIn)
			expiresIn, expiresParseError := strconv.Atoi(expiresInTypeQueryParameter)
			if expiresParseError != nil {
				t.Errorf("expires query parameter was not parsed: %v", expiresParseError)
			}

			accessTokenDuration := time.Minute * time.Duration(client.GetAccessTTL())
			expectedExpiresIn := int(accessTokenDuration / time.Second)

			if expiresIn != expectedExpiresIn {
				t.Errorf("expires in parameter %v did not match %v", expiresIn, expectedExpiresIn)
			}
		})
	}
}

func createTestConfig(t *testing.T) *config.Config {
	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
			},
			{
				Id:           "bar",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				Oidc:         true,
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

func createUri(t *testing.T, uri string, handler func(query url.Values)) *url.URL {
	parsedUri, parseError := url.Parse(uri)
	if parseError != nil {
		t.Fatalf("uri could not be parsed: %v", parseError)
	}

	if handler != nil {
		query := parsedUri.Query()
		handler(query)
		parsedUri.RawQuery = query.Encode()
	}

	return parsedUri
}

func testCreateBody(values ...any) string {
	result := ""
	for index, value := range values {
		result += fmt.Sprintf("%v", value)
		if index > 0 && index%2 != 0 && index < len(values)-1 {
			result += "&"
		} else if index < len(values)-1 {
			result += "="
		}
	}
	return result
}
