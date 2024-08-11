package handler

import (
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
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

	testTokenMissingClientCredentials(t, testConfig)

	testTokenMissingGrandType(t, testConfig)

	testTokenInvalidGrandType(t, testConfig)

	testTokenAuthorizationCodeGrantTypeMissingCodeParameter(t, testConfig)

	testTokenAuthorizationCodeGrantType(t, testConfig)

	testTokenAuthorizationCodeGrantTypePKCE(t, testConfig)

	testTokenNotAllowedHttpMethods(t)
}

func testTokenMissingClientCredentials(t *testing.T, testConfig *config.Config) {
	t.Run("Missing client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		tokenHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/token", nil))

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenMissingGrandType(t *testing.T, testConfig *config.Config) {
	t.Run("Missing grant type", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, "/token", nil)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", createBasicAuth("foo", "bar")))

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
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		body := strings.NewReader(fmt.Sprintf("grant_type=%s", "foobar"))

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", createBasicAuth("foo", "bar")))
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
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		body := strings.NewReader(fmt.Sprintf("grant_type=%s", oauth2.GtAuthorizationCode))

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", createBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
		}
	})
}

func testTokenAuthorizationCodeGrantType(t *testing.T, testConfig *config.Config) {
	t.Run("Authorization code grant type", func(t *testing.T) {
		id := uuid.New()
		authSession := &store.AuthSession{
			Id:                  id.String(),
			Redirect:            "https://example.com/callback",
			AuthURI:             "https://example.com/auth",
			CodeChallenge:       "",
			CodeChallengeMethod: "",
			ClientId:            "foo",
			ResponseType:        string(oauth2.RtCode),
			Scopes:              []string{"foo"},
			State:               "abc",
		}

		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
		sessionManager.StartSession(authSession)

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		body := strings.NewReader(fmt.Sprintf("grant_type=%s&code=%s", oauth2.GtAuthorizationCode, id.String()))

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", createBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}
	})
}

func testTokenAuthorizationCodeGrantTypePKCE(t *testing.T, testConfig *config.Config) {
	t.Run("Authorization code grant type with PKCE", func(t *testing.T) {
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
			Scopes:              []string{"foo"},
			State:               "abc",
		}

		requestValidator := validation.NewRequestValidator(testConfig)
		sessionManager := store.NewSessionManager(testConfig)
		tokenManger := store.NewTokenManager(testConfig, store.NewDefaultKeyLoader(testConfig))
		sessionManager.StartSession(authSession)

		tokenHandler := CreateTokenHandler(requestValidator, sessionManager, tokenManger)

		rr := httptest.NewRecorder()

		body := strings.NewReader(fmt.Sprintf("grant_type=%s&code=%s&code_verifier=%s", oauth2.GtAuthorizationCode, id.String(), "foobar"))

		request := httptest.NewRequest(http.MethodPost, "/token", body)
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", createBasicAuth("foo", "bar")))
		request.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}
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

func createBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
