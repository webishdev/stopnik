package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/pkce"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"strings"
	"testing"
)

func Test_Token(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:         "foo",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				RefreshTTL: 100,
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

	testTokenMissingClientCredentials(t, testConfig)

	testTokenInvalidClientCredentials(t, testConfig)

	testTokenMissingGrandType(t, testConfig)

	testTokenInvalidGrandType(t, testConfig)

	testTokenAuthorizationCodeGrantTypeMissingCodeParameter(t, testConfig)

	testTokenAuthorizationCodeGrantTypeInvalidPKCE(t, testConfig)

	testTokenAuthorizationCodeGrantType(t, testConfig)

	testTokenPasswordGrantType(t, testConfig)

	testTokenClientCredentialsGrantType(t, testConfig)

	testTokenRefreshTokenGrantType(t, testConfig)

	testTokenNotAllowedHttpMethods(t)
}

func testTokenMissingClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		tokenHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/token", nil))

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenInvalidClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/token", nil)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "xxx")))

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func testTokenMissingGrandType(t *testing.T, testConfig *config.Config) {
	t.Run("Missing grant type", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/token", nil)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenInvalidGrandType(t *testing.T, testConfig *config.Config) {
	t.Run("Invalid grant type", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, "foobar",
		)
		body := strings.NewReader(bodyString)

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenAuthorizationCodeGrantTypeMissingCodeParameter(t *testing.T, testConfig *config.Config) {
	t.Run("Authorization code grant type, missing code parameter", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
		)
		body := strings.NewReader(bodyString)

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenAuthorizationCodeGrantTypeInvalidPKCE(t *testing.T, testConfig *config.Config) {
	t.Run("Authorization code grant type with invalid PKCE", func(t *testing.T) {
		id := uuid.New()
		pkceCodeChallenge := pkce.CalculatePKCE(pkce.S256, "foobar")
		authSession := &store.AuthSession{
			Id:                  id.String(),
			Redirect:            "https://example.com/callback",
			AuthURI:             "https://example.com/auth",
			CodeChallenge:       pkceCodeChallenge,
			CodeChallengeMethod: string(pkce.S256),
			ClientId:            "foo",
			ResponseType:        string(oauth2.RtCode),
			Scopes:              []string{"foo:bar", "moo:abc"},
			State:               "xyz",
		}

		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
		sessionManager.StartSession(authSession)

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
			oauth2.ParameterCode, id.String(),
			pkce.ParameterCodeVerifier, "barfoo",
		)
		body := strings.NewReader(bodyString)

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenAuthorizationCodeGrantType(t *testing.T, testConfig *config.Config) {
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
		pkceCodeChallengeMethod := ""
		if test.pkceCodeChallengeMethod != nil {
			pkceCodeChallengeMethod = string(*test.pkceCodeChallengeMethod)
		}
		pkceCodeChallenge := ""
		if test.pkceCodeChallenge != "" {
			pkceCodeChallenge = pkce.CalculatePKCE(*test.pkceCodeChallengeMethod, test.pkceCodeChallenge)
		}
		testMessage := fmt.Sprintf("Authorization code grant type state %v scope %v code challenge %v method %v", test.state, test.scope, pkceCodeChallenge, pkceCodeChallengeMethod)
		t.Run(testMessage, func(t *testing.T) {
			id := uuid.New()
			authSession := &store.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       pkceCodeChallenge,
				CodeChallengeMethod: pkceCodeChallengeMethod,
				ClientId:            "foo",
				ResponseType:        string(oauth2.RtCode),
				Scopes:              []string{"foo:bar", "moo:abc"},
				State:               test.state,
			}

			requestValidator := validation.NewRequestValidator(testConfig)
			sessionManager := store.NewSessionManager(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
			sessionManager.StartSession(authSession)

			tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
				oauth2.ParameterCode, id.String(),
			)
			if test.pkceCodeChallenge != "" && test.pkceCodeChallengeMethod != nil {
				bodyString = testCreateBody(
					oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
					oauth2.ParameterCode, id.String(),
					pkce.ParameterCodeVerifier, test.pkceCodeChallenge,
				)
			}
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/token", body)
			request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			tokenHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			response := rr.Result()

			testTokenValidate(t, tokenManager, response)
		})
	}
}

func testTokenPasswordGrantType(t *testing.T, testConfig *config.Config) {
	t.Run("Password grant type", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtPassword,
			oauth2.ParameterUsername, "foo",
			oauth2.ParameterPassword, "bar",
			oauth2.ParameterScope, "foo:bar moo:abc",
		)
		body := strings.NewReader(bodyString)

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		response := rr.Result()

		testTokenValidate(t, tokenManager, response)
	})
}

func testTokenClientCredentialsGrantType(t *testing.T, testConfig *config.Config) {
	t.Run("Client credentials grant type", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtClientCredentials,
			oauth2.ParameterScope, "foo:bar moo:abc",
		)
		body := strings.NewReader(bodyString)

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		response := rr.Result()

		testTokenValidate(t, tokenManager, response)
	})
}

func testTokenRefreshTokenGrantType(t *testing.T, testConfig *config.Config) {
	t.Run("Authorization code grant type", func(t *testing.T) {
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

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtRefreshToken,
			oauth2.ParameterRefreshToken, accessTokenResponse.RefreshTokenKey,
		)
		body := strings.NewReader(bodyString)

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		response := rr.Result()

		testTokenValidate(t, tokenManager, response)
	})
}

func testTokenNotAllowedHttpMethods(t *testing.T) {
	var testInvalidTokenHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidTokenHttpMethods {
		testMessage := fmt.Sprintf("Token with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			tokenHandler := CreateTokenHandler(&validation.RequestValidator{}, &store.SessionManager{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			tokenHandler.ServeHTTP(rr, httptest.NewRequest(method, "/token", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func testTokenCreateBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
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

func testTokenValidate(t *testing.T, tokenManager *store.TokenManager, response *http.Response) {
	responseBody, bodyReadErr := io.ReadAll(response.Body)

	if bodyReadErr != nil {
		t.Errorf("could not read response body: %v", bodyReadErr)
	}

	if responseBody == nil {
		t.Errorf("response body was nil")
	}

	accessTokenResponse := oauth2.AccessTokenResponse{}
	jsonParseError := json.Unmarshal(responseBody, &accessTokenResponse)
	if jsonParseError != nil {
		t.Errorf("could not parse response body: %v", jsonParseError)
	}

	if accessTokenResponse.AccessTokenKey == "" {
		t.Errorf("access token key was empty")
	}

	_, exists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenKey)

	if !exists {
		t.Errorf("access token was not found in access token manager")
	}

	if accessTokenResponse.TokenType != oauth2.TtBearer {
		t.Errorf("access token type was not bearer")
	}
}
