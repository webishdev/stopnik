package store

import (
	"fmt"
	"reflect"
	"stopnik/internal/config"
	internalHttp "stopnik/internal/http"
	"stopnik/internal/oauth2"
	"testing"
)

func Test_Token(t *testing.T) {
	t.Run("Valid opaque token", func(t *testing.T) {
		testConfig := createTestConfig(t, true, 0)
		tokenManager := NewTokenManager(testConfig, NewDefaultKeyLoader(testConfig))
		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Fatal("client does not exist")
		}

		accessTokenResponse := tokenManager.CreateAccessTokenResponse("foo", client, []string{"abc", "def"})

		if accessTokenResponse.AccessTokenKey == "" {
			t.Error("empty access token")
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
	})
	t.Run("Valid JWT HS256 token", func(t *testing.T) {
		testConfig := createTestConfig(t, false, 0)
		tokenManager := NewTokenManager(testConfig, NewDefaultKeyLoader(testConfig))
		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Fatal("client does not exist")
		}

		accessTokenResponse := tokenManager.CreateAccessTokenResponse("foo", client, []string{"abc", "def"})

		if accessTokenResponse.AccessTokenKey == "" {
			t.Error("empty access token")
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
