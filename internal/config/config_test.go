package config

import (
	"errors"
	"reflect"
	"testing"
)

func TestReadError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return nil, errors.New("test error")
	}, nil)

	_, err := configLoader.LoadConfig("foo.txt")

	if err == nil {
		t.Error("expected error")
	}
}

func TestUnmarshalError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		return errors.New("test error")
	})

	_, err := configLoader.LoadConfig("foo.txt")

	if err == nil {
		t.Error("expected error")
	}
}

func TestDefaultValues(t *testing.T) {
	assertDefaultValues[string](t, "abc", "def", GetOrDefaultString, func(a string) bool {
		return a == "abc"
	})

	assertDefaultValues[string](t, "", "def", GetOrDefaultString, func(a string) bool {
		return a == "def"
	})

	assertDefaultValues[[]string](t, []string{"abc", "def"}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
		return reflect.DeepEqual(a, []string{"abc", "def"})
	})

	assertDefaultValues[[]string](t, []string{}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
		return reflect.DeepEqual(a, []string{"ghi", "jkl"})
	})

	assertDefaultValues[int](t, 22, 23, GetOrDefaultInt, func(a int) bool {
		return a == 22
	})

	assertDefaultValues[int](t, 0, 23, GetOrDefaultInt, func(a int) bool {
		return a == 23
	})
}

func TestEmptyServerHandling(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{},
		}
		return nil
	})

	config, err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	if config.generatedSecret == "" || len(config.generatedSecret) != 16 {
		t.Error("expected generated secret to not be empty")
	}

	serverSecret := config.GetServerSecret()
	if serverSecret != config.generatedSecret {
		t.Error("expected generated secret to be the same")
	}

	authCookieName := config.GetAuthCookieName()
	if authCookieName != "stopnik_auth" {
		t.Error("expected auth cookie name to be 'stopnik_auth'")
	}

	introspectScope := config.GetIntrospectScope()
	if introspectScope != "stopnik:introspect" {
		t.Error("expected introspect scope to be 'stopnik:introspect'")
	}

	revokeScope := config.GetRevokeScope()
	if revokeScope != "stopnik:revoke" {
		t.Error("expected revoke scope to be 'stopnik:revoke'")
	}
}

func TestServerHandling(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Secret:          "5XyLSgKpo5kWrJqm",
				AuthCookieName:  "my_auth",
				IntrospectScope: "i:a",
				RevokeScope:     "r:b",
			},
		}
		return nil
	})

	config, err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	if config.generatedSecret == "" {
		t.Error("expected generated secret to not be empty")
	}

	serverSecret := config.GetServerSecret()
	if serverSecret != "5XyLSgKpo5kWrJqm" {
		t.Error("expected server secret to be '5XyLSgKpo5kWrJqm'")
	}

	authCookieName := config.GetAuthCookieName()
	if authCookieName != "my_auth" {
		t.Error("expected auth cookie name to be 'my_auth'")
	}

	introspectScope := config.GetIntrospectScope()
	if introspectScope != "i:a" {
		t.Error("expected introspect scope to be 'i:a'")
	}

	revokeScope := config.GetRevokeScope()
	if revokeScope != "r:b" {
		t.Error("expected revoke scope to be 'r:b'")
	}
}

func TestUserHandling(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Users: []User{
				{Username: "foo", Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
				{Username: "bar", Password: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"},
				{Username: "moo", Password: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
			},
		}
		return nil
	})

	config, err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	if len(config.Users) != 3 {
		t.Errorf("expected 3 users, got %d", len(config.Users))
	}

	assertUserExistsWithName(t, "foo", config)
	assertUserExistsWithName(t, "bar", config)
	assertUserExistsWithName(t, "moo", config)
}

var invalidUsers = []User{
	{Username: "wrong", Password: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{Username: "empty", Password: ""},
	{Username: "", Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"}}

func TestInvalidUserHandling(t *testing.T) {
	for _, user := range invalidUsers {
		configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
			return make([]byte, 10), nil
		}, func(in []byte, out interface{}) (err error) {
			origin := out.(*Config)
			*origin = Config{
				Users: []User{user},
			}
			return nil
		})

		_, err := configLoader.LoadConfig("foo.txt")

		if err == nil {
			t.Error("expected error when loading config")
		}
	}
}

func TestClientHandling(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Clients: []Client{
				{
					Id:        "foo",
					Secret:    "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects: []string{"http://localhost:8080/callback"},
				},
				{
					Id:         "bar",
					Secret:     "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
					Redirects:  []string{"http://localhost:8080/callback", "https://example.com/callback"},
					AccessTTL:  20,
					RefreshTTL: 60,
					Issuer:     "other",
					Audience:   []string{"one", "two"},
				},
				{
					Id:        "moo",
					Secret:    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
					Redirects: []string{"http://localhost:8080/callback"},
				},
			},
		}
		return nil
	})

	config, err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	if len(config.Clients) != 3 {
		t.Errorf("expected 3 clients, got %d", len(config.Clients))
	}

	assertClientExistsWithId(t, "foo", config)
	assertClientExistsWithId(t, "bar", config)
	assertClientExistsWithId(t, "moo", config)

	assertClientValues(t, config, "foo", 5, 0, "STOPnik", []string{"all"})
	assertClientValues(t, config, "bar", 20, 60, "other", []string{"one", "two"})
}

var invalidClients = []Client{
	{Id: "wrong", Secret: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{Id: "empty", Secret: ""},
	{Id: "", Secret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
	{Id: "no_redirects", Secret: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"},
}

func TestInvalidClientHandling(t *testing.T) {
	for _, client := range invalidClients {
		configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
			return make([]byte, 10), nil
		}, func(in []byte, out interface{}) (err error) {
			origin := out.(*Config)
			*origin = Config{
				Clients: []Client{client},
			}
			return nil
		})

		_, err := configLoader.LoadConfig("foo.txt")

		if err == nil {
			t.Error("expected error when loading config")
		}
	}
}

func assertDefaultValues[T any](t *testing.T, value T, defaultValue T, ccc func(a T, b T) T, expect func(a T) bool) {
	theValue := ccc(value, defaultValue)
	if !expect(theValue) {
		t.Error("expected abc")
	}
}

func assertUserExistsWithName(t *testing.T, username string, config *Config) {
	user, exists := config.GetUser(username)
	if !exists {
		t.Error("expected user")
	}
	if user.Username != username {
		t.Error("expected correct username")
	}
	if user.Password == "" {
		t.Error("expected password")
	}
}

func assertClientExistsWithId(t *testing.T, id string, config *Config) {
	client, exists := config.GetClient(id)
	if !exists {
		t.Error("expected client")
	}
	if client.Id != id {
		t.Error("expected correct id")
	}
	if client.Secret == "" {
		t.Error("expected secret")
	}
}

func assertClientValues(t *testing.T, config *Config, id string, expectedAccessTTL int, expectedRefreshTTL int, expectedIssuer string, expectedAudience []string) {
	client, exits := config.GetClient(id)
	if !exits {
		t.Errorf("expected client with id '%s' to exist", id)
	}

	accessTTL := client.GetAccessTTL()
	if accessTTL != expectedAccessTTL {
		t.Errorf("expected access TTL to be %d, got %d", expectedAccessTTL, accessTTL)
	}

	refreshTTL := client.GetRefreshTTL()
	if refreshTTL != expectedRefreshTTL {
		t.Errorf("expected refresh TTL to be %d, got %d", expectedRefreshTTL, refreshTTL)
	}

	issuer := client.GetIssuer()
	if issuer != expectedIssuer {
		t.Errorf("expected issuer to be '%s', got '%s'", expectedIssuer, issuer)
	}

	audience := client.GetAudience()
	if !reflect.DeepEqual(audience, expectedAudience) {
		t.Errorf("expected audience to be '%s', got '%s'", expectedAudience, audience)
	}
}
