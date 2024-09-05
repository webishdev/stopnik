package token

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/endpoint"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/oidc"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func Test_AccessTokenResponse(t *testing.T) {
	type tokenTestParameter struct {
		opaque          bool
		refreshTokenTTL int
		idTTL           int
	}

	var opaqueTokenParameter = []tokenTestParameter{
		{true, 0, 0},
		{false, 0, 0},
		{true, 100, 0},
		{false, 100, 0},
		{false, 0, 100},
		{false, 100, 100},
		{false, 100, 100},
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
				requestScopes = append(requestScopes, oidc.ScopeOpenId)
			}

			request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
			accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "foo", client, requestScopes, "")

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

			if accessTokenResponse.TokenType != oauth2.TtBearer {
				t.Error("wrong token type")
			}

			authorizationHeader := fmt.Sprintf("%s %s", internalHttp.AuthBearer, accessTokenResponse.AccessTokenValue)

			user, _, scopes, valid := tokenManager.ValidateAccessToken(authorizationHeader)
			if !valid {
				t.Error("user does not exist")
			}

			if user.Username != "foo" {
				t.Error("wrong username")
			}

			if !reflect.DeepEqual(scopes, requestScopes) {
				t.Errorf("assertion error, %v != %v", scopes, requestScopes)
			}

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
		})
	}

	t.Run("Invalid User in token", func(t *testing.T) {
		testConfig := createTestConfig(t, false, 0, 0, "")
		tokenManager := GetTokenManagerInstance()
		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Fatal("client does not exist")
		}

		request := httptest.NewRequest(http.MethodPost, endpoint.Token, nil)
		accessTokenResponse := tokenManager.CreateAccessTokenResponse(request, "bar", client, []string{"abc", "def"}, "")

		_, _, _, valid := tokenManager.ValidateAccessToken(fmt.Sprintf("%s %s", internalHttp.AuthBearer, accessTokenResponse.AccessTokenValue))

		if valid {
			t.Error("should not be valid")
		}
	})
}

func Test_ValidAccessToken(t *testing.T) {
	t.Run("Invalid HTTP Authorization header", func(t *testing.T) {
		createTestConfig(t, false, 0, 0, "")
		tokenManager := GetTokenManagerInstance()

		_, _, _, valid := tokenManager.ValidateAccessToken("foooo")

		if valid {
			t.Error("should not be valid")
		}
	})

	t.Run("Invalid Token value", func(t *testing.T) {
		createTestConfig(t, false, 0, 0, "")
		tokenManager := GetTokenManagerInstance()

		_, _, _, valid := tokenManager.ValidateAccessToken(fmt.Sprintf("%s %s", internalHttp.AuthBearer, "foo"))

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

func createTestConfig(t *testing.T, opaque bool, refreshTokenTTL int, idTTokenTTL int, keyPath string) *config.Config {
	var isOidc = idTTokenTTL > 0
	testConfig := &config.Config{
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
			},
		},
	}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	return testConfig
}
