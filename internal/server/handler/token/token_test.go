package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/session"
	"github.com/webishdev/stopnik/internal/manager/token"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/pkce"
	"github.com/webishdev/stopnik/internal/server/validation"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"uuid"
)

func Test_Token(t *testing.T) {

	testConfigEntries := config.Entries{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				RefreshTTL:   100,
				Scopes:       []string{"foo:bar", "moo:abc"},
				GrantTypes:   []string{"authorization_code", "password", "client_credentials", "refresh_token"},
			},
			{
				Id:         "bar",
				Redirects:  []string{"https://example.com/callback"},
				RefreshTTL: 100,
			},
			{
				Id:           "minimal",
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
	testConfig := &config.Config{}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
	}

	testTokenRefreshTokenGrantType(t, testConfig)

	testTokenRefreshTokenReuse(t, testConfig)

	testTokenRefreshTokenOtherClient(t, testConfig)

	testTokenRefreshTokenScope(t, testConfig)
}

func Test_TokenMissingClientCredentials(t *testing.T) {
	t.Run("Missing client credentials for confidential client", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator()
		authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
		tokenManager := token.GetTokenManagerInstance()

		tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

		rr := httptest.NewRecorder()

		tokenHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, endpoint.Token, nil))

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func Test_TokenInvalidClientCredentials(t *testing.T) {
	t.Run("Invalid client credentials", func(t *testing.T) {
		requestValidator := validation.NewRequestValidator()
		authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
		tokenManager := token.GetTokenManagerInstance()

		tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

		rr := httptest.NewRecorder()

		request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
		request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "xxx")))

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusUnauthorized)
		}
	})
}

func Test_TokenMissingGrandType(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	rr := httptest.NewRecorder()

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))

	tokenHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_TokenInvalidGrandType(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	rr := httptest.NewRecorder()

	bodyString := testCreateBody(
		oauth2.ParameterGrantType, "foobar",
	)
	body := strings.NewReader(bodyString)

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

	tokenHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_TokenAuthorizationCodeGrantTypeMissingCodeParameter(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	rr := httptest.NewRecorder()

	bodyString := testCreateBody(
		oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
	)
	body := strings.NewReader(bodyString)

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

	tokenHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_TokenAuthorizationCodeGrantTypeInvalidPKCE(t *testing.T) {
	id := uuid.New()
	pkceCodeChallenge := pkce.CalculatePKCE(pkce.S256, "foobar")
	authorizationCode := &session.AuthorizationCode{
		Code:                id.String(),
		Redirect:            "https://example.com/callback",
		CodeChallenge:       pkceCodeChallenge,
		CodeChallengeMethod: string(pkce.S256),
		ClientId:            "foo",
		Scopes:              []string{"foo:bar", "moo:abc"},
	}

	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()
	authorizationCodeManager.StartSession(authorizationCode)

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	rr := httptest.NewRecorder()

	bodyString := testCreateBody(
		oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
		oauth2.ParameterCode, id.String(),
		pkce.ParameterCodeVerifier, "barfoo",
	)
	body := strings.NewReader(bodyString)

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

	tokenHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

func Test_TokenAuthorizationCodeGrantType(t *testing.T) {
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
		{"abc", "foo:moo", pkce.GenerateCodeVerifier(), &ccmS256},
		{"abc", "foo:moo", pkce.GenerateCodeVerifier(), &ccmPlain},
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
			authorizationCode := &session.AuthorizationCode{
				Code:                id.String(),
				Redirect:            "https://example.com/callback",
				CodeChallenge:       pkceCodeChallenge,
				CodeChallengeMethod: pkceCodeChallengeMethod,
				ClientId:            "foo",
				Username:            "foo",
				Scopes:              []string{"foo:bar", "moo:abc"},
			}

			requestValidator := validation.NewRequestValidator()
			authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			authorizationCodeManager.StartSession(authorizationCode)

			tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
				oauth2.ParameterCode, id.String(),
				oauth2.ParameterRedirectUri, "https://example.com/callback",
			)
			if test.pkceCodeChallenge != "" && test.pkceCodeChallengeMethod != nil {
				bodyString = testCreateBody(
					oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
					oauth2.ParameterCode, id.String(),
					oauth2.ParameterRedirectUri, "https://example.com/callback",
					pkce.ParameterCodeVerifier, test.pkceCodeChallenge,
				)
			}
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			tokenHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}

			response := rr.Result()

			testTokenValidate(t, tokenManager, response)
		})
	}
}

func Test_TokenAuthorizationCodeGrantTypeInvalidCodeUsage(t *testing.T) {
	type invalidCodeUsageParameter struct {
		name          string
		clientId      string
		clientSecret  string
		username      string
		codeChallenge string
		redirectUri   string
		codeVerifier  string
	}

	codeChallenge := pkce.CalculatePKCE(pkce.S256, "foobar")

	var invalidCodeUsageParameters = []invalidCodeUsageParameter{
		{"Code issued for other client", "bar", "", "foo", "", "https://example.com/callback", ""},
		{"Missing redirect URI", "foo", "bar", "foo", "", "", ""},
		{"Different redirect URI", "foo", "bar", "foo", "", "https://example.com/other", ""},
		{"User not logged in", "foo", "bar", "", "", "https://example.com/callback", ""},
		{"Missing code verifier", "foo", "bar", "foo", codeChallenge, "https://example.com/callback", ""},
	}

	for _, test := range invalidCodeUsageParameters {
		t.Run(test.name, func(t *testing.T) {
			id := uuid.New()
			codeChallengeMethod := ""
			if test.codeChallenge != "" {
				codeChallengeMethod = string(pkce.S256)
			}
			authorizationCode := &session.AuthorizationCode{
				Code:                id.String(),
				Redirect:            "https://example.com/callback",
				CodeChallenge:       test.codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
				ClientId:            "foo",
				Username:            test.username,
				Scopes:              []string{"foo:bar"},
			}

			requestValidator := validation.NewRequestValidator()
			authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
			tokenManager := token.GetTokenManagerInstance()
			authorizationCodeManager.StartSession(authorizationCode)

			tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
				oauth2.ParameterCode, id.String(),
				oauth2.ParameterRedirectUri, test.redirectUri,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth(test.clientId, test.clientSecret)))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			tokenHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
			}

			_, sessionExists := authorizationCodeManager.GetSession(id.String())
			if sessionExists {
				t.Errorf("authorization code was not invalidated after failed usage")
			}
		})
	}
}

func Test_TokenAuthorizationCodeReuse(t *testing.T) {
	code := session.GenerateAuthorizationCode()
	authorizationCode := &session.AuthorizationCode{
		Code:     code,
		Redirect: "https://example.com/callback",
		ClientId: "foo",
		Username: "foo",
		Scopes:   []string{"foo:bar"},
	}

	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()
	authorizationCodeManager.StartSession(authorizationCode)

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	createRequest := func() *http.Request {
		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
			oauth2.ParameterCode, code,
			oauth2.ParameterRedirectUri, "https://example.com/callback",
		)
		request := httptest.NewRequest(http.MethodPost, endpoint.Token, strings.NewReader(bodyString))
		request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")
		return request
	}

	rr := httptest.NewRecorder()
	tokenHandler.ServeHTTP(rr, createRequest())

	if rr.Code != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	accessTokenResponse := oauth2.AccessTokenResponse{}
	jsonParseError := json.Unmarshal(rr.Body.Bytes(), &accessTokenResponse)
	if jsonParseError != nil {
		t.Fatalf("could not parse response body: %v", jsonParseError)
	}

	_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
	if !accessTokenExists {
		t.Fatalf("access token was not found in access token manager")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
	// When a code is used more than once, tokens previously issued based on that code are revoked
	replay := httptest.NewRecorder()
	tokenHandler.ServeHTTP(replay, createRequest())

	if replay.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code for reused code: got %v want %v", replay.Code, http.StatusBadRequest)
	}

	_, accessTokenExists = tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
	if accessTokenExists {
		t.Errorf("access token was not revoked after the code was used again")
	}
}

func Test_TokenCodeVerifierValidation(t *testing.T) {
	codeVerifier := pkce.GenerateCodeVerifier()
	codeChallenge := pkce.CalculatePKCE(pkce.S256, codeVerifier)

	type codeVerifierParameter struct {
		name          string
		codeChallenge string
		codeVerifier  string
		expectedCode  int
	}

	var codeVerifierParameters = []codeVerifierParameter{
		{"Valid code verifier", codeChallenge, codeVerifier, http.StatusOK},
		{"Code verifier does not match", codeChallenge, pkce.GenerateCodeVerifier(), http.StatusBadRequest},
		{"Code verifier too short", pkce.CalculatePKCE(pkce.S256, "short"), "short", http.StatusBadRequest},
		{"Code verifier too long", pkce.CalculatePKCE(pkce.S256, strings.Repeat("a", 129)), strings.Repeat("a", 129), http.StatusBadRequest},
		{"Code verifier with invalid characters", pkce.CalculatePKCE(pkce.S256, codeVerifier[:42]+"+"), codeVerifier[:42] + "+", http.StatusBadRequest},
		{"Missing code verifier", codeChallenge, "", http.StatusBadRequest},
		{"Code verifier without code challenge", "", codeVerifier, http.StatusBadRequest},
	}

	for _, test := range codeVerifierParameters {
		t.Run(test.name, func(t *testing.T) {
			code := session.GenerateAuthorizationCode()
			authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
			authorizationCodeManager.StartSession(&session.AuthorizationCode{
				Code:                code,
				Redirect:            "https://example.com/callback",
				ClientId:            "foo",
				Username:            "foo",
				Scopes:              []string{"foo:bar"},
				CodeChallenge:       test.codeChallenge,
				CodeChallengeMethod: string(pkce.S256),
			})

			bodyString := testCreateBody(
				oauth2.ParameterGrantType, oauth2.GtAuthorizationCode,
				oauth2.ParameterCode, code,
				oauth2.ParameterRedirectUri, "https://example.com/callback",
				pkce.ParameterCodeVerifier, test.codeVerifier,
			)
			request := httptest.NewRequest(http.MethodPost, endpoint.Token, strings.NewReader(bodyString))
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			NewTokenHandler(validation.NewRequestValidator(), authorizationCodeManager, token.GetTokenManagerInstance()).ServeHTTP(rr, request)

			if test.expectedCode == http.StatusOK && rr.Code != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
			}
			if test.expectedCode != http.StatusOK {
				// https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
				testTokenAssertError(t, rr, oauth2.TokenEtInvalidGrant)
			}
		})
	}
}

func Test_TokenPasswordGrantType(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	rr := httptest.NewRecorder()

	bodyString := testCreateBody(
		oauth2.ParameterGrantType, oauth2.GtPassword,
		oauth2.ParameterUsername, "foo",
		oauth2.ParameterPassword, "bar",
		oauth2.ParameterScope, "foo:bar moo:abc",
	)
	body := strings.NewReader(bodyString)

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

	tokenHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	response := rr.Result()

	testTokenValidate(t, tokenManager, response)
}

func Test_TokenNotAllowedGrantTypeOrScope(t *testing.T) {
	type notAllowedParameter struct {
		name          string
		clientId      string
		clientSecret  string
		grantType     oauth2.GrantType
		scope         string
		expectedError oauth2.TokenErrorType
	}

	var notAllowedParameters = []notAllowedParameter{
		{"Reserved introspect scope", "foo", "bar", oauth2.GtPassword, "foo:bar stopnik:introspect", oauth2.TokenEtInvalidScope},
		{"Reserved revoke scope", "foo", "bar", oauth2.GtPassword, "stopnik:revoke", oauth2.TokenEtInvalidScope},
		{"Reserved scope with client credentials", "foo", "bar", oauth2.GtClientCredentials, "stopnik:revoke", oauth2.TokenEtInvalidScope},
		{"Client credentials for public client", "bar", "", oauth2.GtClientCredentials, "foo:bar", oauth2.TokenEtUnauthorizedClient},
		{"Password not allowed by default", "minimal", "bar", oauth2.GtPassword, "", oauth2.TokenEtUnauthorizedClient},
		{"Implicit not allowed by default", "minimal", "bar", oauth2.GtImplicit, "", oauth2.TokenEtUnauthorizedClient},
		{"Client credentials not allowed by default", "minimal", "bar", oauth2.GtClientCredentials, "", oauth2.TokenEtUnauthorizedClient},
		{"Scope not configured for client", "foo", "bar", oauth2.GtPassword, "foo:bar other:scope", oauth2.TokenEtInvalidScope},
	}

	for _, test := range notAllowedParameters {
		t.Run(test.name, func(t *testing.T) {
			requestValidator := validation.NewRequestValidator()
			authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
			tokenManager := token.GetTokenManagerInstance()

			tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

			rr := httptest.NewRecorder()

			bodyString := testCreateBody(
				oauth2.ParameterGrantType, test.grantType,
				oauth2.ParameterUsername, "foo",
				oauth2.ParameterPassword, "bar",
				oauth2.ParameterScope, test.scope,
			)
			body := strings.NewReader(bodyString)

			request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
			request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth(test.clientId, test.clientSecret)))
			request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

			tokenHandler.ServeHTTP(rr, request)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
			}

			errorResponse := oauth2.TokenErrorResponseParameter{}
			jsonError := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
			if jsonError != nil {
				t.Fatal(jsonError)
			}
			if errorResponse.Error != test.expectedError {
				t.Errorf("wrong error: got %v want %v", errorResponse.Error, test.expectedError)
			}
		})
	}
}

func Test_TokenClientCredentialsGrantType(t *testing.T) {
	requestValidator := validation.NewRequestValidator()
	authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
	tokenManager := token.GetTokenManagerInstance()

	tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

	rr := httptest.NewRecorder()

	bodyString := testCreateBody(
		oauth2.ParameterGrantType, oauth2.GtClientCredentials,
		oauth2.ParameterScope, "foo:bar moo:abc",
	)
	body := strings.NewReader(bodyString)

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, body)
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

	tokenHandler.ServeHTTP(rr, request)

	if rr.Code != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	response := rr.Result()

	testTokenValidate(t, tokenManager, response)

	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
	if strings.Contains(rr.Body.String(), oauth2.ParameterRefreshToken) {
		t.Errorf("client credentials response must not contain a refresh token: %s", rr.Body.String())
	}
}

func testTokenRefreshTokenGrantType(t *testing.T, testConfig *config.Config) {
	t.Run("Authorization code grant type", func(t *testing.T) {
		client, _ := testConfig.GetClient("foo")
		user, _ := testConfig.GetUser("foo")
		scopes := []string{"foo:bar", "moo:abc"}

		id := uuid.New()
		authorizationCode := &session.AuthorizationCode{
			Code:                id.String(),
			Redirect:            "https://example.com/callback",
			CodeChallenge:       "",
			CodeChallengeMethod: "",
			ClientId:            client.Id,
			Scopes:              scopes,
		}

		requestValidator := validation.NewRequestValidator()
		authorizationCodeManager := session.GetAuthorizationCodeManagerInstance()
		tokenManager := token.GetTokenManagerInstance()
		authorizationCodeManager.StartSession(authorizationCode)

		request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
		accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, user.Username, client, nil, scopes, nil, "", "", "")

		tokenHandler := NewTokenHandler(requestValidator, authorizationCodeManager, tokenManager)

		rr := httptest.NewRecorder()

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtRefreshToken,
			oauth2.ParameterRefreshToken, accessTokenResponse.RefreshTokenValue,
		)
		body := strings.NewReader(bodyString)

		request = httptest.NewRequest(http.MethodPost, endpoint.Token, body)
		request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(rr, request)

		if rr.Code != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}

		response := rr.Result()

		testTokenValidate(t, tokenManager, response)

		// Refresh tokens are rotated, so the used refresh token is no longer valid
		replay := httptest.NewRecorder()
		replayRequest := httptest.NewRequest(http.MethodPost, endpoint.Token, strings.NewReader(bodyString))
		replayRequest.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth("foo", "bar")))
		replayRequest.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")

		tokenHandler.ServeHTTP(replay, replayRequest)

		if replay.Code != http.StatusBadRequest {
			t.Errorf("handler returned wrong status code for reused refresh token: got %v want %v", replay.Code, http.StatusBadRequest)
		}
	})
}

func testTokenRefreshTokenReuse(t *testing.T, testConfig *config.Config) {
	t.Run("Refresh token reuse revokes the grant", func(t *testing.T) {
		tokenManager := token.GetTokenManagerInstance()
		client, _ := testConfig.GetClient("foo")
		initialResponse := tokenManager.CreateAccessTokenResponse(httptest.NewRequest(http.MethodPost, endpoint.Token, nil), "foo", client, nil, []string{"foo:bar"}, nil, "", "", "")
		otherGrantResponse := tokenManager.CreateAccessTokenResponse(httptest.NewRequest(http.MethodPost, endpoint.Token, nil), "foo", client, nil, []string{"foo:bar"}, nil, "", "", "")

		rr := testTokenRefreshRequest(t, initialResponse.RefreshTokenValue, "", "foo", "bar")
		if rr.Code != http.StatusOK {
			t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
		}
		refreshedResponse := testTokenParseResponse(t, rr)

		// https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2
		replay := testTokenRefreshRequest(t, initialResponse.RefreshTokenValue, "", "foo", "bar")
		testTokenAssertError(t, replay, oauth2.TokenEtInvalidGrant)

		_, accessTokenExists := tokenManager.GetAccessToken(refreshedResponse.AccessTokenValue)
		_, refreshTokenExists := tokenManager.GetRefreshToken(refreshedResponse.RefreshTokenValue)
		if accessTokenExists || refreshTokenExists {
			t.Error("tokens obtained with the reused refresh token should have been revoked")
		}

		_, initialAccessTokenExists := tokenManager.GetAccessToken(initialResponse.AccessTokenValue)
		if initialAccessTokenExists {
			t.Error("access token of the same grant should have been revoked")
		}

		_, otherAccessTokenExists := tokenManager.GetAccessToken(otherGrantResponse.AccessTokenValue)
		_, otherRefreshTokenExists := tokenManager.GetRefreshToken(otherGrantResponse.RefreshTokenValue)
		if !otherAccessTokenExists || !otherRefreshTokenExists {
			t.Error("tokens of another grant should stay active")
		}
	})
}

func testTokenRefreshTokenOtherClient(t *testing.T, testConfig *config.Config) {
	t.Run("Refresh token of other client", func(t *testing.T) {
		tokenManager := token.GetTokenManagerInstance()
		client, _ := testConfig.GetClient("foo")
		initialResponse := tokenManager.CreateAccessTokenResponse(httptest.NewRequest(http.MethodPost, endpoint.Token, nil), "foo", client, nil, []string{"foo:bar"}, nil, "", "", "")

		bodyString := testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtRefreshToken,
			oauth2.ParameterRefreshToken, initialResponse.RefreshTokenValue,
			oauth2.ParameterClientId, "bar",
		)
		request := httptest.NewRequest(http.MethodPost, endpoint.Token, strings.NewReader(bodyString))
		request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		NewTokenHandler(validation.NewRequestValidator(), session.GetAuthorizationCodeManagerInstance(), tokenManager).ServeHTTP(rr, request)

		testTokenAssertError(t, rr, oauth2.TokenEtInvalidGrant)

		// The refresh token was not consumed by the other client
		ownerResponse := testTokenRefreshRequest(t, initialResponse.RefreshTokenValue, "", "foo", "bar")
		if ownerResponse.Code != http.StatusOK {
			t.Errorf("owner of the refresh token should still be able to use it, got %v", ownerResponse.Code)
		}
	})
}

func testTokenRefreshTokenScope(t *testing.T, testConfig *config.Config) {
	t.Run("Refresh token with scope", func(t *testing.T) {
		tokenManager := token.GetTokenManagerInstance()
		client, _ := testConfig.GetClient("foo")
		initialResponse := tokenManager.CreateAccessTokenResponse(httptest.NewRequest(http.MethodPost, endpoint.Token, nil), "foo", client, nil, []string{"foo:bar", "moo:abc"}, nil, "", "", "")

		// https://datatracker.ietf.org/doc/html/rfc6749#section-6
		wider := testTokenRefreshRequest(t, initialResponse.RefreshTokenValue, "foo:bar moo:abc other:scope", "foo", "bar")
		testTokenAssertError(t, wider, oauth2.TokenEtInvalidScope)

		narrower := testTokenRefreshRequest(t, initialResponse.RefreshTokenValue, "foo:bar", "foo", "bar")
		if narrower.Code != http.StatusOK {
			t.Fatalf("handler returned wrong status code: got %v want %v", narrower.Code, http.StatusOK)
		}
		narrowerResponse := testTokenParseResponse(t, narrower)

		accessToken, accessTokenExists := tokenManager.GetAccessToken(narrowerResponse.AccessTokenValue)
		if !accessTokenExists || !reflect.DeepEqual(accessToken.Scopes, []string{"foo:bar"}) {
			t.Errorf("expected access token with narrower scope, got %v", accessToken)
		}

		withoutScope := testTokenRefreshRequest(t, narrowerResponse.RefreshTokenValue, "", "foo", "bar")
		if withoutScope.Code != http.StatusOK {
			t.Fatalf("handler returned wrong status code: got %v want %v", withoutScope.Code, http.StatusOK)
		}
		withoutScopeResponse := testTokenParseResponse(t, withoutScope)
		accessToken, _ = tokenManager.GetAccessToken(withoutScopeResponse.AccessTokenValue)
		if !reflect.DeepEqual(accessToken.Scopes, []string{"foo:bar"}) {
			t.Errorf("expected access token to keep the scope of the refresh token, got %v", accessToken.Scopes)
		}
	})
}

func testTokenRefreshRequest(t *testing.T, refreshToken string, scope string, clientId string, clientSecret string) *httptest.ResponseRecorder {
	t.Helper()
	bodyString := testCreateBody(
		oauth2.ParameterGrantType, oauth2.GtRefreshToken,
		oauth2.ParameterRefreshToken, refreshToken,
	)
	if scope != "" {
		bodyString = testCreateBody(
			oauth2.ParameterGrantType, oauth2.GtRefreshToken,
			oauth2.ParameterRefreshToken, refreshToken,
			oauth2.ParameterScope, scope,
		)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint.Token, strings.NewReader(bodyString))
	request.Header.Add(internalHttp.Authorization, fmt.Sprintf("Basic %s", testTokenCreateBasicAuth(clientId, clientSecret)))
	request.Header.Add(internalHttp.ContentType, "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	NewTokenHandler(validation.NewRequestValidator(), session.GetAuthorizationCodeManagerInstance(), token.GetTokenManagerInstance()).ServeHTTP(rr, request)
	return rr
}

func testTokenParseResponse(t *testing.T, rr *httptest.ResponseRecorder) oauth2.AccessTokenResponse {
	t.Helper()
	accessTokenResponse := oauth2.AccessTokenResponse{}
	if jsonError := json.Unmarshal(rr.Body.Bytes(), &accessTokenResponse); jsonError != nil {
		t.Fatalf("could not parse response body: %v", jsonError)
	}
	return accessTokenResponse
}

func testTokenAssertError(t *testing.T, rr *httptest.ResponseRecorder, expectedError oauth2.TokenErrorType) {
	t.Helper()
	if rr.Code != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
	errorResponse := oauth2.TokenErrorResponseParameter{}
	if jsonError := json.Unmarshal(rr.Body.Bytes(), &errorResponse); jsonError != nil {
		t.Fatalf("could not parse error response: %v", jsonError)
	}
	if errorResponse.Error != expectedError {
		t.Errorf("wrong error: got %v want %v", errorResponse.Error, expectedError)
	}
}

func Test_TokenNotAllowedHttpMethods(t *testing.T) {
	var testInvalidTokenHttpMethods = []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range testInvalidTokenHttpMethods {
		testMessage := fmt.Sprintf("Token with unsupported method %s", method)
		t.Run(testMessage, func(t *testing.T) {
			tokenHandler := NewTokenHandler(&validation.RequestValidator{}, &session.CodeManager{}, &token.Manager{})

			rr := httptest.NewRecorder()

			tokenHandler.ServeHTTP(rr, httptest.NewRequest(method, endpoint.Token, nil))

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

func testTokenValidate(t *testing.T, tokenManager *token.Manager, response *http.Response) {
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

	if accessTokenResponse.AccessTokenValue == "" {
		t.Errorf("access token key was empty")
	}

	_, exists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)

	if !exists {
		t.Errorf("access token was not found in access token manager")
	}

	if accessTokenResponse.TokenType != oauth2.TtBearer {
		t.Errorf("access token type was not bearer")
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
