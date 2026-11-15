package token

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type tokenTestParameter struct {
	opaque          bool
	refreshTokenTTL int
	idTTL           int
	authCode        string
}

func Test_AccessTokenResponse(t *testing.T) {
	var opaqueTokenParameter = []tokenTestParameter{
		{true, 0, 0, ""},
		{true, 0, 0, "abcd"},
		{false, 0, 0, ""},
		{false, 0, 0, "abcd"},
		{true, 100, 0, ""},
		{true, 100, 0, "abcd"},
		{false, 100, 0, ""},
		{false, 100, 0, "abcd"},
		{false, 0, 100, ""},
		{false, 0, 100, "abcd"},
		{false, 100, 100, ""},
		{false, 100, 100, "abcd"},
		{false, 100, 100, ""},
		{false, 100, 100, "abcd"},
	}

	for _, test := range opaqueTokenParameter {
		testMessage := fmt.Sprintf("Valid token opaque %t refreshTTL %d idTTL %d", test.opaque, test.refreshTokenTTL, test.idTTL)
		t.Run(testMessage, func(t *testing.T) {
			testConfig := createTestConfig(t, test.opaque, test.refreshTokenTTL, test.idTTL, "../../../.test_files/ecdsa521key.pem")
			tokenManager := GetTokenManagerInstance()
			client, clientExists := testConfig.GetClient("foo")
			if !clientExists {
				t.Fatal("client does not exist")
			}

			requestScopes := []string{"abc", "def"}
			if test.idTTL > 0 {
				requestScopes = append(requestScopes, oidc.ScopeOpenId, oidc.ScopeOfflineAccess, oidc.ScopeProfile, oidc.ScopeAddress, oidc.ScopeEmail, oidc.ScopePhone)
			}

			request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, requestScopes, nil, "", test.authCode, "")

			assertTokenResponse(t, accessTokenResponse, test, client)

			authorizationHeader := fmt.Sprintf("%s %s", internalHttp.AuthBearer, accessTokenResponse.AccessTokenValue)

			assertAuthorizationHeader(t, tokenManager, authorizationHeader, requestScopes)

			accessToken, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)

			if !accessTokenExists {
				t.Error("access token does not exist")
			}

			if accessToken.Key != accessTokenResponse.AccessTokenValue {
				t.Error("wrong access token")
			}

			refreshToken, refreshTokenExists := tokenManager.GetRefreshToken(accessTokenResponse.RefreshTokenValue)

			if test.refreshTokenTTL == 0 && refreshTokenExists {
				t.Error("refresh token should not exists")
			}

			if test.refreshTokenTTL > 0 && !refreshTokenExists {
				t.Error("refresh token should exists")
			}

			if test.refreshTokenTTL > 0 && refreshToken.Key != accessTokenResponse.RefreshTokenValue {
				t.Error("wrong refresh token")
			}

			if test.authCode == "" {

				tokenManager.RevokeRefreshToken(refreshToken)
				_, refreshTokenExists = tokenManager.GetRefreshToken(accessTokenResponse.RefreshTokenValue)
				if refreshTokenExists {
					t.Error("refresh token should not exists")
				}

				tokenManager.RevokeAccessToken(accessToken)
				_, accessTokenExists = tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
				if accessTokenExists {
					t.Error("access token should not exists")
				}
			} else {
				tokenManager.RevokeAccessTokenByAuthorizationCode(test.authCode)
				_, accessTokenExists = tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
				if accessTokenExists {
					t.Error("access token should not exists")
				}
			}
		})
	}
}

func Test_ForwardAuthClientId(t *testing.T) {
	var opaqueTokenParameter = []tokenTestParameter{
		{true, 0, 0, ""},
		{true, 0, 0, "abcd"},
		{false, 0, 0, ""},
		{false, 0, 0, "abcd"},
		{true, 0, 0, ""},
		{true, 0, 0, "abcd"},
		{false, 0, 0, ""},
		{false, 0, 0, "abcd"},
		{false, 0, 0, ""},
		{false, 0, 0, "abcd"},
		{false, 0, 0, ""},
		{false, 0, 0, "abcd"},
		{false, 0, 0, ""},
		{false, 0, 0, "abcd"},
	}

	for _, test := range opaqueTokenParameter {
		testMessage := fmt.Sprintf("Valid token opaque %t", test.opaque)
		t.Run(testMessage, func(t *testing.T) {
			testConfig := createTestConfig(t, test.opaque, 0, 0, "../../../.test_files/ecdsa521key.pem")
			forwardAuthClient, forwardAuthClientExists := testConfig.GetForwardAuthClient()
			if !forwardAuthClientExists {
				t.Fatal("forward auth client does not exist")
			}

			tokenManagerSingleton = nil

			tokenManager := GetTokenManagerInstance()

			requestScopes := []string{"abc", "def"}
			if test.idTTL > 0 {
				requestScopes = append(requestScopes, oidc.ScopeOpenId, oidc.ScopeOfflineAccess, oidc.ScopeProfile, oidc.ScopeAddress, oidc.ScopeEmail, oidc.ScopePhone)
			}

			request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", forwardAuthClient, nil, requestScopes, nil, "", test.authCode, "")

			assertTokenResponse(t, accessTokenResponse, test, forwardAuthClient)
		})
	}
}

func Test_InvalidUserInToken(t *testing.T) {
	testConfig := createTestConfig(t, false, 0, 0, "")
	tokenManager := GetTokenManagerInstance()
	client, clientExists := testConfig.GetClient("foo")
	if !clientExists {
		t.Fatal("client does not exist")
	}

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "bar", client, nil, []string{"abc", "def"}, nil, "", "", "")

	_, valid := tokenManager.validateAccessTokenHeader(fmt.Sprintf("%s %s", internalHttp.AuthBearer, accessTokenResponse.AccessTokenValue))

	if valid {
		t.Error("should not be valid")
	}
}

func Test_ValidAccessToken(t *testing.T) {
	t.Run("Invalid HTTP Authorization header", func(t *testing.T) {
		createTestConfig(t, false, 0, 0, "")
		tokenManager := GetTokenManagerInstance()

		_, valid := tokenManager.validateAccessTokenHeader("foooo")

		if valid {
			t.Error("should not be valid")
		}
	})

	t.Run("Invalid Token value", func(t *testing.T) {
		createTestConfig(t, false, 0, 0, "")
		tokenManager := GetTokenManagerInstance()

		_, valid := tokenManager.validateAccessTokenHeader(fmt.Sprintf("%s %s", internalHttp.AuthBearer, "foo"))

		if valid {
			t.Error("should not be valid")
		}
	})
}

func Test_HashToken(t *testing.T) {
	type hashTokenParameter struct {
		token         string
		hashAlgorithm crypto.HashAlgorithm
		expectedHash  string
	}

	var hashTokenParameters = []hashTokenParameter{
		{"dNZX1hEZ9wBCzNL40Upu646bdzQA", crypto.SHA256, "wfgvmE9VxjAudsl9lc6TqA"},
		{"dNZX1hEZ9wBCzNL40Upu646bdzQA", crypto.SHA384, "phZaPQJosyg-qi-OIYyQ3xJB9wsHYEEz"},
		{"dNZX1hEZ9wBCzNL40Upu646bdzQA", crypto.SHA512, "8xltSlOGYrWy8W9yNvRlEth1i_bXW-JROWPLvCv5zog"},
		{"rvArgQKPbBDJkeTHwoIAOQVkV8J0_i8PhrRKyLDaKkk.iY6nzJoIb2dRXBoqHAa3Yb6gkHveTXbnM6PGtmoKXvo", crypto.SHA256, "glbC70G_oVT5IyHiFg6v1Q"},
	}

	for _, test := range hashTokenParameters {
		testMessage := fmt.Sprintf("Hash access token %s with %v", test.token, test.hashAlgorithm)
		t.Run(testMessage, func(t *testing.T) {
			hashedToken := hashToken(test.hashAlgorithm, test.token)

			if hashedToken != test.expectedHash {
				t.Errorf("hashed token does not match, %v != %v", hashedToken, test.expectedHash)
			}
		})
	}

}

func Test_TokenIssuerNotFromHostHeader(t *testing.T) {
	testConfig := createTestConfig(t, false, 100, 100, "../../../.test_files/ecdsa521key.pem")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")

	// The Host header can be manipulated by a client and must not be used for the issuer
	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	request.Host = "evil.example"
	requestScopes := []string{oidc.ScopeOpenId, oidc.ScopeOfflineAccess}
	accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, requestScopes, nil, "", "", "")

	tokenValues := map[string]string{
		"access token":  accessTokenResponse.AccessTokenValue,
		"refresh token": accessTokenResponse.RefreshTokenValue,
		"id token":      accessTokenResponse.IdTokenValue,
	}
	for name, tokenValue := range tokenValues {
		parsedToken, parseError := jwt.ParseInsecure([]byte(tokenValue))
		if parseError != nil {
			t.Fatalf("could not parse %s: %v", name, parseError)
		}
		issuer, _ := parsedToken.Issuer()
		if issuer != "https://auth.example.com" {
			t.Errorf("issuer of %s was %s, expected the configured issuer", name, issuer)
		}
	}
}

func Test_TokenWithoutConfiguredKey(t *testing.T) {
	testConfig := createTestConfig(t, false, 100, 100, "")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	requestScopes := []string{oidc.ScopeOpenId, oidc.ScopeOfflineAccess}
	accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, requestScopes, nil, "", "", "")

	// Without configured keys every token is signed with the ephemeral server key, never with the server secret
	for _, tokenValue := range []string{accessTokenResponse.AccessTokenValue, accessTokenResponse.RefreshTokenValue, accessTokenResponse.IdTokenValue} {
		assertVerifiesWithPublicKeys(t, tokenValue)
		if _, secretError := jwt.Parse([]byte(tokenValue), jwt.WithKey(jwa.HS256(), []byte(testConfig.GetServerSecret()))); secretError == nil {
			t.Error("token must not be signed with the server secret")
		}
	}
}

// assertVerifiesWithPublicKeys verifies the token with the public keys, which are served by the JWKS endpoint.
func assertVerifiesWithPublicKeys(t *testing.T, tokenValue string) jwt.Token {
	t.Helper()
	keySet := jwk.NewSet()
	for _, managedKey := range key.GetKeyMangerInstance().GetAllKeys() {
		publicKey, publicKeyError := (*managedKey.Key).PublicKey()
		if publicKeyError != nil {
			t.Fatal(publicKeyError)
		}
		if addKeyError := keySet.AddKey(publicKey); addKeyError != nil {
			t.Fatal(addKeyError)
		}
	}
	parsedToken, parseError := jwt.Parse([]byte(tokenValue), jwt.WithKeySet(keySet))
	if parseError != nil {
		t.Fatalf("token could not be verified with the public keys: %v", parseError)
	}
	return parsedToken
}

func Test_CreateIdToken(t *testing.T) {
	testConfig := createTestConfig(t, false, 100, 100, "../../../.test_files/ecdsa521key.pem")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")
	accessTokenCount, refreshTokenCount := tokenManager.TokenCount(client.Id)

	request := httptest.NewRequest(http.MethodGet, endpoint.Authorization, nil)
	idToken := tokenManager.CreateIdToken(request, "foo", client, nil, []string{oidc.ScopeOpenId, oidc.ScopeOfflineAccess}, nil, "abc")

	parsedIdToken := assertVerifiesWithPublicKeys(t, idToken)
	if parsedIdToken.Has(oidc.ClaimAtHash) {
		t.Error("id token without access token must not contain at_hash")
	}
	if nonce, _ := parsedIdToken.Field(oidc.ClaimNonce); nonce != "abc" {
		t.Errorf("expected nonce abc, got %v", nonce)
	}

	newAccessTokenCount, newRefreshTokenCount := tokenManager.TokenCount(client.Id)
	if newAccessTokenCount != accessTokenCount || newRefreshTokenCount != refreshTokenCount {
		t.Error("creating an id token must not store access or refresh tokens")
	}

	if unknownUserIdToken := tokenManager.CreateIdToken(request, "unknown", client, nil, []string{oidc.ScopeOpenId}, nil, ""); unknownUserIdToken != "" {
		t.Error("expected no id token for unknown user")
	}
}

func Test_CreateAccessTokenResponseWithoutRefreshToken(t *testing.T) {
	testConfig := createTestConfig(t, false, 100, 0, "../../../.test_files/ecdsa521key.pem")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")
	_, refreshTokenCount := tokenManager.TokenCount(client.Id)

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	accessTokenResponse := tokenManager.CreateAccessTokenResponseWithoutRefreshToken(request, "foo", client, nil, []string{"abc"}, nil, "")

	if accessTokenResponse.AccessTokenValue == "" || accessTokenResponse.RefreshTokenValue != "" {
		t.Error("expected an access token, but no refresh token")
	}
	if _, newRefreshTokenCount := tokenManager.TokenCount(client.Id); newRefreshTokenCount != refreshTokenCount {
		t.Error("no refresh token must be stored")
	}
}

func Test_AuthorizationCodeReuseRevokesRefreshToken(t *testing.T) {
	testConfig := createTestConfig(t, false, 100, 0, "../../../.test_files/ecdsa521key.pem")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, []string{"abc"}, nil, "", "reused-code", "")

	_, refreshTokenTaken := tokenManager.TakeRefreshToken(accessTokenResponse.RefreshTokenValue)
	if !refreshTokenTaken {
		t.Fatal("refresh token should exist")
	}
	refreshedResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, []string{"abc"}, nil, "", "", "")

	tokenManager.RevokeAccessTokenByAuthorizationCode("reused-code")

	_, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenValue)
	if accessTokenExists {
		t.Error("access token issued for the code should have been revoked")
	}

	// Tokens of other grants are not affected
	_, refreshedRefreshTokenExists := tokenManager.GetRefreshToken(refreshedResponse.RefreshTokenValue)
	if !refreshedRefreshTokenExists {
		t.Error("refresh token of another grant should stay active")
	}
}

func Test_RefreshTokenKeepsGrant(t *testing.T) {
	testConfig := createTestConfig(t, false, 100, 0, "../../../.test_files/ecdsa521key.pem")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")

	request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
	initialResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, []string{"abc"}, nil, "", "code-with-refresh", "")
	refreshToken, _ := tokenManager.TakeRefreshToken(initialResponse.RefreshTokenValue)
	refreshedResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, nil, []string{"abc"}, nil, "", "", refreshToken.GrantId)

	refreshedRefreshToken, refreshedRefreshTokenExists := tokenManager.GetRefreshToken(refreshedResponse.RefreshTokenValue)
	if !refreshedRefreshTokenExists || refreshedRefreshToken.GrantId != refreshToken.GrantId || refreshToken.GrantId == "" {
		t.Fatal("refreshed tokens should belong to the same grant")
	}

	// Reusing the code also revokes the refresh token obtained by refreshing
	tokenManager.RevokeAccessTokenByAuthorizationCode("code-with-refresh")

	_, refreshedRefreshTokenExists = tokenManager.GetRefreshToken(refreshedResponse.RefreshTokenValue)
	_, refreshedAccessTokenExists := tokenManager.GetAccessToken(refreshedResponse.AccessTokenValue)
	if refreshedRefreshTokenExists || refreshedAccessTokenExists {
		t.Error("tokens of the grant should have been revoked after reuse of the code")
	}
}

func Test_GetAuthorizationHeaderValue(t *testing.T) {
	type headerParameter struct {
		header   string
		expected string
		valid    bool
	}

	var headerParameters = []headerParameter{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc.def-ghi_jkl~", "abc.def-ghi_jkl~", true},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Bearer abc def", "", false},
		{"Bearer  abc", "", false},
		{"Basic QmVhcmVyIGFiYw==", "", false},
		{"xBearer abc", "", false},
		{"Bearerabc", "", false},
		{"Basic Bearer abc", "", false},
		{"", "", false},
	}

	for _, test := range headerParameters {
		t.Run(test.header, func(t *testing.T) {
			value := getAuthorizationHeaderValue(test.header)
			if test.valid && (value == nil || *value != test.expected) {
				t.Errorf("expected %q, got %v", test.expected, value)
			}
			if !test.valid && value != nil {
				t.Errorf("expected no value, got %q", *value)
			}
		})
	}
}

func Test_ValidateAccessTokenRequest(t *testing.T) {
	testConfig := createTestConfig(t, false, 0, 0, "../../../.test_files/ecdsa521key.pem")
	tokenManager := GetTokenManagerInstance()
	client, _ := testConfig.GetClient("foo")
	accessTokenResponse := tokenManager.CreateAccessTokenResponse(httptest.NewRequest(http.MethodPost, endpoint.Token, nil), "foo", client, nil, []string{"abc"}, nil, "", "", "")
	accessToken := accessTokenResponse.AccessTokenValue

	type requestParameter struct {
		name        string
		method      string
		contentType string
		header      string
		body        string
		valid       bool
	}

	var requestParameters = []requestParameter{
		{"Authorization header", http.MethodGet, "", "Bearer " + accessToken, "", true},
		{"Form-encoded body", http.MethodPost, "application/x-www-form-urlencoded", "", "access_token=" + accessToken, true},
		{"Form-encoded body with charset", http.MethodPost, "application/x-www-form-urlencoded; charset=utf-8", "", "access_token=" + accessToken, true},
		{"Body without form content type", http.MethodPost, "text/plain", "", "access_token=" + accessToken, false},
		{"Query parameter is ignored", http.MethodGet, "", "", "", false},
		{"Header and body at the same time", http.MethodPost, "application/x-www-form-urlencoded", "Bearer " + accessToken, "access_token=" + accessToken, false},
	}

	for _, test := range requestParameters {
		t.Run(test.name, func(t *testing.T) {
			target := "/userinfo"
			if test.name == "Query parameter is ignored" {
				target = "/userinfo?access_token=" + accessToken
			}
			request := httptest.NewRequest(test.method, target, strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set(internalHttp.ContentType, test.contentType)
			}
			if test.header != "" {
				request.Header.Set(internalHttp.Authorization, test.header)
			}
			if _, valid := tokenManager.ValidateAccessTokenRequest(request); valid != test.valid {
				t.Errorf("result %t did not match %t", valid, test.valid)
			}
		})
	}
}

func assertAuthorizationHeader(t *testing.T, tokenManager *Manager, authorizationHeader string, requestScopes []string) {
	validAccessToken, valid := tokenManager.validateAccessTokenHeader(authorizationHeader)
	if !valid {
		t.Error("user does not exist")
	}
	user := validAccessToken.User
	scopes := validAccessToken.Scopes

	if user.Username != "foo" {
		t.Error("wrong username")
	}

	if !reflect.DeepEqual(scopes, requestScopes) {
		t.Errorf("assertion error, %v != %v", scopes, requestScopes)
	}
}

func assertTokenResponse(t *testing.T, accessTokenResponse oauth2.AccessTokenResponse, test tokenTestParameter, client *config.Client) {
	if accessTokenResponse.AccessTokenValue == "" {
		t.Error("empty access token")
	}

	if test.refreshTokenTTL == 0 && accessTokenResponse.RefreshTokenValue != "" {
		t.Error("refresh token should not exists")
	}

	if test.refreshTokenTTL > 0 && accessTokenResponse.RefreshTokenValue == "" {
		t.Error("refresh token should exists")
	}

	if test.idTTL > 0 && !client.Oidc {
		t.Error("client should be configured for OIDC because of id token")
	}

	if test.idTTL == 0 && accessTokenResponse.IdTokenValue != "" {
		t.Error("id token should not exists")
	}

	if test.idTTL > 0 && accessTokenResponse.IdTokenValue == "" {
		t.Error("id token should exists")
	}

	if test.idTTL > 0 && accessTokenResponse.IdTokenValue != "" {
		parsedIdToken := assertVerifiesWithPublicKeys(t, accessTokenResponse.IdTokenValue)

		subject, _ := parsedIdToken.Subject()
		if subject != "foo" {
			t.Error("expected subject to be 'foo'")
		}
	}

	if accessTokenResponse.TokenType != oauth2.TtBearer {
		t.Error("wrong token type")
	}
}

func createTestConfig(t *testing.T, opaque bool, refreshTokenTTL int, idTTokenTTL int, keyPath string) *config.Config {
	var isOidc = idTTokenTTL > 0
	testConfigEntries := config.Entries{
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				OpaqueToken:  opaque,
				RefreshTTL:   refreshTokenTTL,
				IdTTL:        idTTokenTTL,
				Oidc:         isOidc,
				PrivateKey:   keyPath,
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				UserProfile: config.UserProfile{
					PreferredUserName: "foofoo",
					GivenName:         "Hans",
					FamilyName:        "Mayer",
				},
				UserInformation: config.UserInformation{
					Address: &config.UserAddress{
						Street:     "Main Street 123",
						PostalCode: "98765",
						City:       "Maintown",
					},
				},
			},
		},
	}
	testConfig := &config.Config{
		Server: config.Server{
			Issuer: "https://auth.example.com",
			ForwardAuth: config.ForwardAuth{
				Enabled:     true,
				ExternalUrl: "http://localhost:8082",
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
