package store

import (
	"fmt"
	"reflect"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"testing"
)

type tokenTestParameter struct {
	opaque          bool
	refreshTokenTTL int
}

var opaqueTokenParameter = []tokenTestParameter{
	{true, 0},
	{false, 0},
	{true, 100},
	{false, 100},
}

func Test_Token(t *testing.T) {
	for _, test := range opaqueTokenParameter {
		testMessage := fmt.Sprintf("Valid token opaque %t refreshTTL %d", test.opaque, test.refreshTokenTTL)
		t.Run(testMessage, func(t *testing.T) {
			testConfig := createTestConfig(t, test.opaque, test.refreshTokenTTL)
			tokenManager := NewTokenManager(testConfig, NewDefaultKeyLoader(testConfig))
			client, clientExists := testConfig.GetClient("foo")
			if !clientExists {
				t.Fatal("client does not exist")
			}

			accessTokenResponse := tokenManager.CreateAccessTokenResponse("foo", client, []string{"abc", "def"})

			if accessTokenResponse.AccessTokenKey == "" {
				t.Error("empty access token")
			}

			if test.refreshTokenTTL == 0 && accessTokenResponse.RefreshTokenKey != "" {
				t.Error("refresh token should not exists")
			}

			if test.refreshTokenTTL > 0 && accessTokenResponse.RefreshTokenKey == "" {
				t.Error("refresh token should exists")
			}

			if accessTokenResponse.TokenType != oauth2.TtBearer {
				t.Error("wrong token type")
			}

			authorizationHeader := fmt.Sprintf("%s %s", internalHttp.AuthBearer, accessTokenResponse.AccessTokenKey)

			user, scopes, userExists := tokenManager.ValidateAccessToken(authorizationHeader)
			if !userExists {
				t.Error("user does not exist")
			}

			if user.Username != "foo" {
				t.Error("wrong username")
			}

			if !reflect.DeepEqual(scopes, []string{"abc", "def"}) {
				t.Errorf("assertion error, %v != %v", scopes, []string{"abc", "def"})
			}

			accessToken, accessTokenExists := tokenManager.GetAccessToken(accessTokenResponse.AccessTokenKey)

			if !accessTokenExists {
				t.Error("access token does not exist")
			}

			if accessToken.Key != accessTokenResponse.AccessTokenKey {
				t.Error("wrong access token")
			}

			refreshToken, refreshTokenExists := tokenManager.GetRefreshToken(accessTokenResponse.RefreshTokenKey)

			if test.refreshTokenTTL == 0 && refreshTokenExists {
				t.Error("refresh token should not exists")
			}

			if test.refreshTokenTTL > 0 && !refreshTokenExists {
				t.Error("refresh token should exists")
			}

			if test.refreshTokenTTL > 0 && refreshToken.Key != accessTokenResponse.RefreshTokenKey {
				t.Error("wrong refresh token")
			}

			tokenManager.RevokeRefreshToken(refreshToken)
			_, refreshTokenExists = tokenManager.GetRefreshToken(accessTokenResponse.RefreshTokenKey)
			if refreshTokenExists {
				t.Error("refresh token should not exists")
			}

			tokenManager.RevokeAccessToken(accessToken)
			_, accessTokenExists = tokenManager.GetAccessToken(accessTokenResponse.AccessTokenKey)
			if accessTokenExists {
				t.Error("access token should not exists")
			}
		})
	}

	t.Run("Invalid HTTP Authorization header", func(t *testing.T) {
		testConfig := createTestConfig(t, false, 0)
		tokenManager := NewTokenManager(testConfig, NewDefaultKeyLoader(testConfig))

		_, _, valid := tokenManager.ValidateAccessToken("foooo")

		if valid {
			t.Error("should not be valid")
		}
	})

	t.Run("Invalid Token value", func(t *testing.T) {
		testConfig := createTestConfig(t, false, 0)
		tokenManager := NewTokenManager(testConfig, NewDefaultKeyLoader(testConfig))

		_, _, valid := tokenManager.ValidateAccessToken(fmt.Sprintf("%s %s", internalHttp.AuthBearer, "foo"))

		if valid {
			t.Error("should not be valid")
		}
	})

	t.Run("Invalid User in token", func(t *testing.T) {
		testConfig := createTestConfig(t, false, 0)
		tokenManager := NewTokenManager(testConfig, NewDefaultKeyLoader(testConfig))
		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Fatal("client does not exist")
		}

		accessTokenResponse := tokenManager.CreateAccessTokenResponse("bar", client, []string{"abc", "def"})

		_, _, valid := tokenManager.ValidateAccessToken(fmt.Sprintf("%s %s", internalHttp.AuthBearer, accessTokenResponse.AccessTokenKey))

		if valid {
			t.Error("should not be valid")
		}
	})
}

func createTestConfig(t *testing.T, opaque bool, refreshTokenTTL int) *config.Config {
	testConfig := &config.Config{
		Clients: []config.Client{
			{
				Id:          "foo",
				Secret:      "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:   []string{"https://example.com/callback"},
				OpaqueToken: opaque,
				RefreshTTL:  refreshTokenTTL,
			},
		},
		Users: []config.User{
			{
				Username: "foo",
				Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
			},
		},
	}
	setupError := testConfig.Setup()
	if setupError != nil {
		t.Fatal(setupError)
	}

	return testConfig
}
