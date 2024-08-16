package introspect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/server/validation"
	"github.com/webishdev/stopnik/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
				Introspect: true,
			},
			{
				Id:         "bar",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				RefreshTTL: 100,
				Introspect: false,
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

	testIntrospectMissingClientCredentials(t, testConfig)

	testIntrospectInvalidClientCredentials(t, testConfig)

	testIntrospectEmptyToken(t, testConfig)

	testIntrospectInvalidToken(t, testConfig)

	testIntrospect(t, testConfig)

	testIntrospectWithoutHint(t, testConfig)

	testIntrospectDisabled(t, testConfig)

	testIntrospectNotAllowedHttpMethods(t)
}

func testIntrospectMissingClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
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
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/introspect", nil)
		request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "xxx")))

		introspectHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func testIntrospectEmptyToken(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Introspect empty %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

			introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/introspect", body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			introspectHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			response := rr.Result()

			introspectResponse := testIntrospectParse(t, response)

			if introspectResponse.Active {
				t.Errorf("Token should not be active")
			}
		})
	}
}

func testIntrospectInvalidToken(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Introspect invalid %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

			introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterCode, "foo-no-bar",
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/introspect", body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			introspectHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			response := rr.Result()

			introspectResponse := testIntrospectParse(t, response)

			if introspectResponse.Active {
				t.Errorf("Token should not be active")
			}
		})
	}
}

func testIntrospect(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Introspect %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			client, _ := testConfig.GetClient("foo")
			user, _ := testConfig.GetUser("foo")
			scopes := []string{"foo:bar", "moo:abc"}

			id := uuid.New()
			authSession := &store.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseType:        string(oauth2.RtCode),
				Scopes:              scopes,
				State:               "xyz",
			}

			requestValidator := validation.NewRequestValidator(testConfig)
			sessionManager := store.NewSessionManager(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
			sessionManager.StartSession(authSession)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(user.Username, client, scopes)

			introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

			token := accessTokenResponse.AccessTokenKey
			if test.tokenHint == oauth2.ItRefreshToken {
				token = accessTokenResponse.RefreshTokenKey
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, token,
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/introspect", body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			introspectHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			response := rr.Result()

			introspectResponse := testIntrospectParse(t, response)

			if !introspectResponse.Active {
				t.Errorf("Token should be active")
			}
		})
	}
}

func testIntrospectWithoutHint(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenType oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Introspect without token hint %v", test.tokenType)
		t.Run(testMessage, func(t *testing.T) {
			client, _ := testConfig.GetClient("foo")
			user, _ := testConfig.GetUser("foo")
			scopes := []string{"foo:bar", "moo:abc"}

			id := uuid.New()
			authSession := &store.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseType:        string(oauth2.RtCode),
				Scopes:              scopes,
				State:               "xyz",
			}

			requestValidator := validation.NewRequestValidator(testConfig)
			sessionManager := store.NewSessionManager(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
			sessionManager.StartSession(authSession)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(user.Username, client, scopes)

			introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

			token := accessTokenResponse.AccessTokenKey
			if test.tokenType == oauth2.ItRefreshToken {
				token = accessTokenResponse.RefreshTokenKey
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, token,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/introspect", body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			introspectHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			response := rr.Result()

			introspectResponse := testIntrospectParse(t, response)

			if !introspectResponse.Active {
				t.Errorf("Token should be active")
			}
		})
	}
}

func testIntrospectDisabled(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Introspect for disabled client %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			client, _ := testConfig.GetClient("bar")
			user, _ := testConfig.GetUser("foo")
			scopes := []string{"foo:bar", "moo:abc"}

			id := uuid.New()
			authSession := &store.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseType:        string(oauth2.RtCode),
				Scopes:              scopes,
				State:               "xyz",
			}

			requestValidator := validation.NewRequestValidator(testConfig)
			sessionManager := store.NewSessionManager(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
			sessionManager.StartSession(authSession)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(user.Username, client, scopes)

			introspectHandler := CreateIntrospectHandler(testConfig, requestValidator, tokenManager)

			token := accessTokenResponse.AccessTokenKey
			if test.tokenHint == oauth2.ItRefreshToken {
				token = accessTokenResponse.RefreshTokenKey
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, token,
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/introspect", body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("bar", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			introspectHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusServiceUnavailable)
			}
		})
	}
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

func testIntrospectParse(t *testing.T, response *http.Response) IntrospectResponse {
	responseBody, bodyReadErr := io.ReadAll(response.Body)

	if bodyReadErr != nil {
		t.Errorf("could not read response body: %v", bodyReadErr)
	}

	if responseBody == nil {
		t.Errorf("response body was nil")
	}

	introspectResponse := IntrospectResponse{}
	jsonParseError := json.Unmarshal(responseBody, &introspectResponse)
	if jsonParseError != nil {
		t.Errorf("could not parse response body: %v", jsonParseError)
	}

	return introspectResponse
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

func testTokenCreateBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
