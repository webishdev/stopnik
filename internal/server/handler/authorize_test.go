package handler

import (
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"stopnik/internal/pkce"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"strconv"
	"testing"
	"time"
)

func Test_Authorize(t *testing.T) {

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

	testNoClientId(t, testConfig)

	testInvalidClientId(t, testConfig)

	testInvalidRedirect(t, testConfig)

	testInvalidResponseType(t, testConfig)

	testNoCookeExists(t, testConfig)

	testAuthorizationGrant(t, testConfig)

	testImplicitGrant(t, testConfig)

	testNotAllowedHttpMethods(t)

}

func testNotAllowedHttpMethods(t *testing.T) {
	var testInvalidAuthorizeHttpMethods = []string{
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidAuthorizeHttpMethods {
		testMessage := fmt.Sprintf("Authorize with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			authorizeHandler := CreateAuthorizeHandler(&validation.RequestValidator{}, &internalHttp.CookieManager{}, &store.SessionManager{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			authorizeHandler.ServeHTTP(rr, httptest.NewRequest(method, "/authorize", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testImplicitGrant(t *testing.T, testConfig *config.Config) {
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
			parsedUri := createUri(t, "/authorize", func(query url.Values) {
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
			requestValidator := validation.NewRequestValidator(testConfig)
			sessionManager := store.NewSessionManager(testConfig)
			cookieManager := internalHttp.NewCookieManager(testConfig)
			tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

			client, _ := testConfig.GetClient("foo")
			user, _ := testConfig.GetUser("foo")
			cookie, _ := cookieManager.CreateCookie(user.Username)

			authorizeHandler := CreateAuthorizeHandler(requestValidator, cookieManager, sessionManager, tokenManger)

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, parsedUri.String(), nil)
			request.AddCookie(&cookie)

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			locationHeader := rr.Header().Get(internalHttp.Location)
			location, parseError := url.Parse(locationHeader)
			if parseError != nil {
				t.Errorf("location header could not be parsed: %v", parseError)
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

func testAuthorizationGrant(t *testing.T, testConfig *config.Config) {
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
			parsedUri := createUri(t, "/authorize", func(query url.Values) {
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
			requestValidator := validation.NewRequestValidator(testConfig)
			sessionManager := store.NewSessionManager(testConfig)
			cookieManager := internalHttp.NewCookieManager(testConfig)

			user, _ := testConfig.GetUser("foo")
			cookie, _ := cookieManager.CreateCookie(user.Username)

			authorizeHandler := CreateAuthorizeHandler(requestValidator, cookieManager, sessionManager, &store.TokenManager{})

			rr := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, parsedUri.String(), nil)
			request.AddCookie(&cookie)

			authorizeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusFound {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
			}

			locationHeader := rr.Header().Get(internalHttp.Location)
			location, parseError := url.Parse(locationHeader)
			if parseError != nil {
				t.Errorf("location header could not be parsed: %v", parseError)
			}

			codeQueryParameter := location.Query().Get(oauth2.ParameterCode)

			if codeQueryParameter == "" {
				t.Errorf("code query parameter was not set")
			}

			stateQueryParameter := location.Query().Get(oauth2.ParameterState)

			if stateQueryParameter != test.state {
				t.Errorf("state parameter %v did not match: %v", stateQueryParameter, test.state)
			}

			session, sessionExists := sessionManager.GetSession(codeQueryParameter)
			if !sessionExists {
				t.Errorf("session does not exist: %v", codeQueryParameter)
			}

			if session.CodeChallenge != pkceCodeChallenge {
				t.Errorf("session code challenge %v did not match: %v", session.CodeChallenge, pkceCodeChallenge)
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

func testNoCookeExists(t *testing.T, testConfig *config.Config) bool {
	return t.Run("No cookie exists", func(t *testing.T) {
		parsedUri := createUri(t, "/authorize", func(query url.Values) {
			query.Set(oauth2.ParameterClientId, "foo")
			query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
			query.Set(oauth2.ParameterResponseType, oauth2.ParameterCode)
		})
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		cookieManager := internalHttp.NewCookieManager(testConfig)

		authorizeHandler := CreateAuthorizeHandler(requestValidator, cookieManager, sessionManager, &store.TokenManager{})

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

	})
}

func testInvalidResponseType(t *testing.T, testConfig *config.Config) bool {
	return t.Run("Invalid response type", func(t *testing.T) {
		parsedUri := createUri(t, "/authorize", func(query url.Values) {
			query.Set(oauth2.ParameterClientId, "foo")
			query.Set(oauth2.ParameterRedirectUri, "https://example.com/callback")
			query.Set(oauth2.ParameterResponseType, "abc")
		})
		requestValidator := validation.NewRequestValidator(testConfig)

		authorizeHandler := CreateAuthorizeHandler(requestValidator, &internalHttp.CookieManager{}, &store.SessionManager{}, &store.TokenManager{})

		rr := httptest.NewRecorder()

		authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

		if rr.Code != http.StatusFound {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusFound)
		}

		locationHeader := rr.Header().Get(internalHttp.Location)
		location, parseError := url.Parse(locationHeader)
		if parseError != nil {
			t.Errorf("location header could not be parsed: %v", parseError)
		}

		errorQueryParameter := location.Query().Get(oauth2.ParameterError)

		errorType, errorTypeExists := oauth2.ErrorTypeFromString(errorQueryParameter)

		if !errorTypeExists {
			t.Errorf("error type could not be parsed: %v", errorQueryParameter)
		}

		if errorType != oauth2.EtInvalidRequest {
			t.Errorf("error type was not Invalid: %v", errorQueryParameter)
		}
	})
}

func testInvalidRedirect(t *testing.T, testConfig *config.Config) {
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
			parsedUri := createUri(t, "/authorize", func(query url.Values) {
				query.Set(oauth2.ParameterClientId, "foo")
				query.Set(oauth2.ParameterRedirectUri, test.redirect)
			})

			requestValidator := validation.NewRequestValidator(testConfig)

			authorizeHandler := CreateAuthorizeHandler(requestValidator, &internalHttp.CookieManager{}, &store.SessionManager{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

			if rr.Code != test.status {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, test.status)
			}
		})

	}
}

func testInvalidClientId(t *testing.T, testConfig *config.Config) bool {
	return t.Run("Invalid client id", func(t *testing.T) {
		parsedUri := createUri(t, "/authorize", func(query url.Values) {
			query.Set(oauth2.ParameterClientId, "bar")
		})

		requestValidator := validation.NewRequestValidator(testConfig)

		authorizeHandler := CreateAuthorizeHandler(requestValidator, &internalHttp.CookieManager{}, &store.SessionManager{}, &store.TokenManager{})

		rr := httptest.NewRecorder()

		authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsedUri.String(), nil))

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testNoClientId(t *testing.T, testConfig *config.Config) bool {
	return t.Run("No client id provided", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)

		authorizeHandler := CreateAuthorizeHandler(requestValidator, &internalHttp.CookieManager{}, &store.SessionManager{}, &store.TokenManager{})

		rr := httptest.NewRecorder()

		authorizeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize", nil))

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
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
