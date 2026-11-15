package revoke

import (
	"encoding/base64"
	"fmt"
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
	"uuid"
)

func Test_Revoke(t *testing.T) {

	testConfigEntries := config.Entries{
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
	testConfig := &config.Config{}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
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

	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), string(oauth2.TokenEtInvalidClient)) {
		t.Errorf("handler returned wrong response: got %v %s want %v", rr.Code, rr.Body.String(), http.StatusUnauthorized)
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
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, user.Username, client, nil, scopes, nil, "", "", "")

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
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, user.Username, client, nil, scopes, nil, "", "", "")

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
		testMessage := fmt.Sprintf("Revoke own token without revoke flag %v", test.tokenHint)
		t.Run(testMessage, func(t *testing.T) {
			tokenManager := token.GetTokenManagerInstance()
			accessTokenResponse := testCreateTokens(t, testConfig, "bar")

			tokenValue := accessTokenResponse.AccessTokenValue
			if test.tokenHint == oauth2.ItRefreshToken {
				tokenValue = accessTokenResponse.RefreshTokenValue
			}

			rr := testRevokeRequest(t, tokenValue, test.tokenHint, testTokenCreateBasicAuth("bar", "bar"))

			// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
			// A client may always revoke its own tokens
			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			_, accessTokenExists := tokenManager.GetAccessToken(tokenValue)
			_, refreshTokenExists := tokenManager.GetRefreshToken(tokenValue)
			if accessTokenExists || refreshTokenExists {
				t.Errorf("token should have been revoked")
			}
		})
	}
}

func Test_RevokeBoundToClient(t *testing.T) {
	testConfig := createRevokeTestConfig(t)
	tokenManager := token.GetTokenManagerInstance()

	t.Run("Client can not revoke tokens of other clients", func(t *testing.T) {
		for _, tokenHint := range []oauth2.IntrospectTokenType{oauth2.ItAccessToken, oauth2.ItRefreshToken, ""} {
			accessTokenResponse := testCreateTokens(t, testConfig, "bar")
			tokenValue := accessTokenResponse.AccessTokenValue
			if tokenHint == oauth2.ItRefreshToken {
				tokenValue = accessTokenResponse.RefreshTokenValue
			}

			rr := testRevokeRequest(t, tokenValue, tokenHint, testTokenCreateBasicAuth("foo", "bar"))

			// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
			_, refreshTokenExists := tokenManager.GetRefreshToken(accessTokenResponse.RefreshTokenValue)
			if !accessTokenExists || !refreshTokenExists {
				t.Errorf("tokens of another client must stay active, token hint %q", tokenHint)
			}
		}
	})

	t.Run("Revoking a refresh token revokes the access token of the same grant", func(t *testing.T) {
		accessTokenResponse := testCreateTokens(t, testConfig, "foo")
		otherAccessTokenResponse := testCreateTokens(t, testConfig, "foo")

		rr := testRevokeRequest(t, accessTokenResponse.RefreshTokenValue, oauth2.ItRefreshToken, testTokenCreateBasicAuth("foo", "bar"))

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
		if accessTokenExists {
			t.Errorf("access token of the revoked refresh token should be inactive")
		}

		_, otherAccessTokenExists := tokenManager.GetAccessToken(otherAccessTokenResponse.AccessTokenValue)
		if !otherAccessTokenExists {
			t.Errorf("access token of another grant should stay active")
		}
	})

	t.Run("Public client can revoke own tokens", func(t *testing.T) {
		accessTokenResponse := testCreateTokens(t, testConfig, "public")

		bodyString := testCreateBody(
			oauth2.ParameterClientId, "public",
			oauth2.ParameterToken, accessTokenResponse.AccessTokenValue,
		)
		request := httptest.NewRequest(http.MethodPost, endpoint.Revoke, strings.NewReader(bodyString))
		request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()
		NewRevokeHandler(validation.NewRequestValidator(), tokenManager).ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
		if accessTokenExists {
			t.Errorf("access token should have been revoked")
		}
	})

	t.Run("Access token with revoke scope can revoke tokens of other clients", func(t *testing.T) {
		accessTokenResponse := testCreateTokens(t, testConfig, "bar")
		client, _ := testConfig.GetClient("foo")
		request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
		adminTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, []string{testConfig.GetRevokeScope()}, nil, "", "", "")

		rr := testRevokeRequestWithHeader(t, accessTokenResponse.AccessTokenValue, oauth2.ItAccessToken, internalHttp.AuthBearer+" "+adminTokenResponse.AccessTokenValue)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
		if accessTokenExists {
			t.Errorf("access token should have been revoked")
		}
	})

	t.Run("Access token with revoke scope of client without revoke flag is rejected", func(t *testing.T) {
		accessTokenResponse := testCreateTokens(t, testConfig, "foo")
		client, _ := testConfig.GetClient("bar")
		request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
		adminTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, []string{testConfig.GetRevokeScope()}, nil, "", "", "")

		rr := testRevokeRequestWithHeader(t, accessTokenResponse.AccessTokenValue, oauth2.ItAccessToken, internalHttp.AuthBearer+" "+adminTokenResponse.AccessTokenValue)

		// https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), string(oauth2.TokenEtInsufficientScope)) {
			t.Errorf("handler returned wrong response: got %v %s want %v", rr.Code, rr.Body.String(), http.StatusForbidden)
		}

		_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
		if !accessTokenExists {
			t.Errorf("access token should stay active")
		}
	})
}

func createRevokeTestConfig(t *testing.T) *config.Config {
	testConfigEntries := config.Entries{
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
			},
			{
				Id:         "public",
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
	testConfig := &config.Config{}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
	}
	return testConfig
}

func testCreateTokens(t *testing.T, testConfig *config.Config, clientId string) oauth2.AccessTokenResponse {
	t.Helper()
	client, clientExists := testConfig.GetClient(clientId)
	if !clientExists {
		t.Fatalf("client %s does not exist", clientId)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	return token.GetTokenManagerInstance().CreateAccessTokenResponse(request, "foo", client, nil, []string{"foo:bar"}, nil, "", "", "")
}

func testRevokeRequest(t *testing.T, tokenValue string, tokenHint oauth2.IntrospectTokenType, basicAuth string) *httptest.ResponseRecorder {
	t.Helper()
	return testRevokeRequestWithHeader(t, tokenValue, tokenHint, fmt.Sprintf("Basic %s", basicAuth))
}

func testRevokeRequestWithHeader(t *testing.T, tokenValue string, tokenHint oauth2.IntrospectTokenType, authorizationHeader string) *httptest.ResponseRecorder {
	t.Helper()
	bodyString := testCreateBody(oauth2.ParameterToken, tokenValue)
	if tokenHint != "" {
		bodyString = testCreateBody(
			oauth2.ParameterToken, tokenValue,
			oauth2.ParameterTokenTypeHint, tokenHint,
		)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint.Revoke, strings.NewReader(bodyString))
	request.Header.Add(internalHttp.Authorization, authorizationHeader)
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	NewRevokeHandler(validation.NewRequestValidator(), token.GetTokenManagerInstance()).ServeHTTP(rr, request)
	return rr
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
