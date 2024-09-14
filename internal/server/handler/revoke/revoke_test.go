package revoke

import (
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/server/validation"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_Revoke(t *testing.T) {

	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				RefreshTTL:   100,
				Revoke:       true,
			},
			{
				Id:           "bar",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				RefreshTTL:   100,
				Revoke:       false,
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

	testRevoke(t, testConfig)

	testRevokeWithoutHint(t, testConfig)

	testRevokeDisabled(t, testConfig)
}

func Test_RevokeMissingClientCredentials(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	tokenManager := token.GetTokenManagerInstance()

	revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

	rr := httptest.NewRecorder()

	revokeHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, endpoint.Revoke, nil))

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
	}
}

func Test_RevokeInvalidClientCredentials(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	tokenManager := token.GetTokenManagerInstance()

	revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

	rr := httptest.NewRecorder()

	request := httptest.NewRequest(http.MethodPost, endpoint.Revoke, nil)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "xxx")))

	revokeHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
	}
}

func Test_RevokeEmptyToken(t *testing.T) {
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
			requestValidator := validation.NewRequestValidator()
			tokenManager := token.GetTokenManagerInstance()

			revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Revoke, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

		})
	}
}

func Test_RevokeInvalidToken(t *testing.T) {
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
			requestValidator := validation.NewRequestValidator()
			tokenManager := token.GetTokenManagerInstance()

			revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterCode, "foo-no-bar",
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Revoke, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

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
			authSession := &session.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseTypes:       []oauth2.ResponseType{oauth2.RtCode},
				Scopes:              scopes,
				State:               "xyz",
			}

			requestValidator := validation.NewRequestValidator()
			sessionManager := session.GetAuthSessionManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			sessionManager.StartSession(authSession)
			request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, user.Username, client, nil, scopes, "")

			revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

			accessTokenValue := accessTokenResponse.AccessTokenValue
			if test.tokenHint == oauth2.ItRefreshToken {
				accessTokenValue = accessTokenResponse.RefreshTokenValue
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, accessTokenValue,
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request = httptest.NewRequest(http.MethodPost, endpoint.Revoke, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			if test.tokenHint == oauth2.ItAccessToken {
				_, accessTokenExists := tokenManager.GetAccessToken(accessTokenValue)
				if accessTokenExists {
					t.Errorf("access token should have been revoked")
				}
			} else if test.tokenHint == oauth2.ItRefreshToken {
				_, refreshTokenExists := tokenManager.GetRefreshToken(accessTokenValue)
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
			authSession := &session.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseTypes:       []oauth2.ResponseType{oauth2.RtCode},
				Scopes:              scopes,
				State:               "xyz",
			}

			requestValidator := validation.NewRequestValidator()
			sessionManager := session.GetAuthSessionManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			sessionManager.StartSession(authSession)
			request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, user.Username, client, nil, scopes, "")

			revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

			accessTokenValue := accessTokenResponse.AccessTokenValue
			if test.tokenHint == oauth2.ItRefreshToken {
				accessTokenValue = accessTokenResponse.RefreshTokenValue
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, accessTokenValue,
			)
			body := strings.NewReader(bodyString)

			request = httptest.NewRequest(http.MethodPost, endpoint.Revoke, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			if test.tokenHint == oauth2.ItAccessToken {
				_, accessTokenExists := tokenManager.GetAccessToken(accessTokenValue)
				if accessTokenExists {
					t.Errorf("access token should have been revoked")
				}
			} else if test.tokenHint == oauth2.ItRefreshToken {
				_, refreshTokenExists := tokenManager.GetRefreshToken(accessTokenValue)
				if refreshTokenExists {
					t.Errorf("refresh token should have been revoked")
				}
			}

		})
	}
}

func testRevokeDisabled(t *testing.T, testConfig *config.Config) {
	type revokeParameter struct {
		tokenHint oauth2.IntrospectTokenType
	}

	var revokeParameters = []revokeParameter{
		{oauth2.ItAccessToken},
		{oauth2.ItRefreshToken},
	}

	for _, test := range revokeParameters {
		testMessage := fmt.Sprintf("Revoke for disabld client %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			client, _ := testConfig.GetClient("bar")
			user, _ := testConfig.GetUser("foo")
			scopes := []string{"foo:bar", "moo:abc"}

			id := uuid.New()
			authSession := &session.AuthSession{
				Id:                  id.String(),
				Redirect:            "https://example.com/callback",
				AuthURI:             "https://example.com/auth",
				CodeChallenge:       "",
				CodeChallengeMethod: "",
				ClientId:            client.Id,
				ResponseTypes:       []oauth2.ResponseType{oauth2.RtCode},
				Scopes:              scopes,
				State:               "xyz",
			}

			requestValidator := validation.NewRequestValidator()
			sessionManager := session.GetAuthSessionManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			sessionManager.StartSession(authSession)
			request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, user.Username, client, nil, scopes, "")

			revokeHandler := NewRevokeHandler(requestValidator, tokenManager)

			accessTokenValue := accessTokenResponse.AccessTokenValue
			if test.tokenHint == oauth2.ItRefreshToken {
				accessTokenValue = accessTokenResponse.RefreshTokenValue
			}

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterToken, accessTokenValue,
				oauth2.ParameterTokenTypeHint, test.tokenHint,
			)
			body := strings.NewReader(bodyString)

			request = httptest.NewRequest(http.MethodPost, endpoint.Revoke, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("bar", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			revokeHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusServiceUnavailable)
			}

		})
	}
}

func Test_RevokeNotAllowedHttpMethods(t *testing.T) {
	var testInvalidRevokeHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	testConfig := &config.Config{}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	for _, method := range testInvalidRevokeHttpMethods {
		testMessage := fmt.Sprintf("Revoke with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			revokeHandler := NewRevokeHandler(&validation.RequestValidator{}, &token.Manager{})

			rr := httptest.NewRecorder()

			revokeHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Revoke, nil))

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
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
