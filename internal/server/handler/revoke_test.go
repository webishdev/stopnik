package handler

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"stopnik/internal/config"
	"stopnik/internal/oauth2"
	"stopnik/internal/server/validation"
	"stopnik/internal/store"
	"strings"
	"testing"
)

func Test_Revoke(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:         "foo",
				Secret:     "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:  []string{"https://example.com/callback"},
				RefreshTTL: 100,
				Revoke:     true,
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

	testRevokeMissingClientCredentials(t, testConfig)

	testRevokeInvalidClientCredentials(t, testConfig)

	testRevokeEmptyToken(t, testConfig)

	testRevokeInvalidToken(t, testConfig)

	testRevoke(t, testConfig)

	testRevokeWithoutHint(t, testConfig)

	testRevokeNotAllowedHttpMethods(t)
}

func testRevokeMissingClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		revokeHandler := CreateRevokeHandler(testConfig, requestValidator, tokenManager)

		rr := httptest.NewRecorder()

		revokeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/revoke", nil))

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func testRevokeInvalidClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Invalid client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		revokeHandler := CreateRevokeHandler(testConfig, requestValidator, tokenManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/revoke", nil)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "xxx")))

		revokeHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func testRevokeEmptyToken(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Revoke empty %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

			revokeHandler := CreateRevokeHandler(testConfig, requestValidator, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/revoke", body)
			request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

		})
	}
}

func testRevokeInvalidToken(t *testing.T, testConfig *config.Config) {
	type introspectParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var introspectParameters = []introspectParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range introspectParameters {
		testMessage := fmt.Sprintf("Revoke invalid %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator(testConfig)
			tokenManager := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

			revokeHandler := CreateRevokeHandler(testConfig, requestValidator, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterCode, "foo-no-bar",
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/revoke", body)
			request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}
		})
	}
}

func testRevoke(t *testing.T, testConfig *config.Config) {
	type revokeParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var revokeParameters = []revokeParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range revokeParameters {
		testMessage := fmt.Sprintf("Revoke %v", test.tokenHint)
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

			revokeHandler := CreateRevokeHandler(testConfig, requestValidator, tokenManager)

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

			request := httptest.NewRequest(http.MethodPost, "/revoke", body)
			request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			if test.tokenHint == oauth2.ItAccessToken {
				_, accessTokenExists := tokenManager.GetAccessToken(token)
				if accessTokenExists {
					t.Errorf("access token should have been revoked")
				}
			} else if test.tokenHint == oauth2.ItRefreshToken {
				_, refreshTokenExists := tokenManager.GetRefreshToken(token)
				if refreshTokenExists {
					t.Errorf("refresh token should have been revoked")
				}
			}

		})
	}
}

func testRevokeWithoutHint(t *testing.T, testConfig *config.Config) {
	type revokeParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var revokeParameters = []revokeParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range revokeParameters {
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

			revokeHandler := CreateRevokeHandler(testConfig, requestValidator, tokenManager)

			token := accessTokenResponse.AccessTokenKey
			if test.tokenHint == oauth2.ItRefreshToken {
				token = accessTokenResponse.RefreshTokenKey
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, token,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, "/revoke", body)
			request.Header.Add("Authorization", fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			if test.tokenHint == oauth2.ItAccessToken {
				_, accessTokenExists := tokenManager.GetAccessToken(token)
				if accessTokenExists {
					t.Errorf("access token should have been revoked")
				}
			} else if test.tokenHint == oauth2.ItRefreshToken {
				_, refreshTokenExists := tokenManager.GetRefreshToken(token)
				if refreshTokenExists {
					t.Errorf("refresh token should have been revoked")
				}
			}

		})
	}
}

func testRevokeNotAllowedHttpMethods(t *testing.T) {
	var testInvalidRevokeHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidRevokeHttpMethods {
		testMessage := fmt.Sprintf("Revoke with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			revokeHandler := CreateRevokeHandler(&config.Config{}, &validation.RequestValidator{}, &store.TokenManager{})

			rr := httptest.NewRecorder()

			revokeHandler.ServeHTTP(rr, httptest.NewRequest(method, "/revoke", nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}
