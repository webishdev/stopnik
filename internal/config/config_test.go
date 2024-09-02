package config

import (
	"errors"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"reflect"
	"testing"
)

func Test_Load(t *testing.T) {
	t.Run("readError", readError)
	t.Run("unmarshalError", unmarshalError)
}

func Test_DefaultValues(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		assertDefaultValues[string](t, "abc", "def", GetOrDefaultString, func(a string) bool {
			return a == "abc"
		})

		assertDefaultValues[string](t, "", "def", GetOrDefaultString, func(a string) bool {
			return a == "def"
		})
	})

	t.Run("[]string", func(t *testing.T) {
		assertDefaultValues[[]string](t, []string{"abc", "def"}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"abc", "def"})
		})

		assertDefaultValues[[]string](t, []string{}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"ghi", "jkl"})
		})
	})

	t.Run("int", func(t *testing.T) {
		assertDefaultValues[int](t, 22, 23, GetOrDefaultInt, func(a int) bool {
			return a == 22
		})

		assertDefaultValues[int](t, 0, 23, GetOrDefaultInt, func(a int) bool {
			return a == 23
		})
	})
}

func Test_Server(t *testing.T) {
	t.Run("empty", emptyServerConfiguration)
	t.Run("simple", simpleServerConfiguration)
}

func Test_UI(t *testing.T) {
	t.Run("empty", emptyUIConfiguration)
	t.Run("simple", simpleUIConfiguration)
}

func Test_Users(t *testing.T) {
	t.Run("valid", validUsers)
	t.Run("invalid", invalidUsers)
}

func Test_Clients(t *testing.T) {
	t.Run("valid", validClients)
	t.Run("invalid", invalidClients)
}

func readError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return nil, errors.New("test error")
	}, nil)

	err := configLoader.LoadConfig("foo.txt")

	if err == nil {
		t.Error("expected error")
	}
}

func unmarshalError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		return errors.New("test error")
	})

	err := configLoader.LoadConfig("foo.txt")

	if err == nil {
		t.Error("expected error")
	}
}

func emptyServerConfiguration(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
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

	messageCookieName := config.GetMessageCookieName()
	if messageCookieName != "stopnik_message" {
		t.Error("expected message cookie name to be 'stopnik_message'")
	}

	introspectScope := config.GetIntrospectScope()
	if introspectScope != "stopnik:introspect" {
		t.Error("expected introspect scope to be 'stopnik:introspect'")
	}

	revokeScope := config.GetRevokeScope()
	if revokeScope != "stopnik:revoke" {
		t.Error("expected revoke scope to be 'stopnik:revoke'")
	}

	sessionTimeout := config.GetSessionTimeoutSeconds()
	if sessionTimeout != 3600 {
		t.Error("expected session timeout to be 3600")
	}

	forwardAuthEnabled := config.GetForwardAuthEnabled()
	if forwardAuthEnabled {
		t.Error("expected forward auth enabled to be false")
	}

	forwardAuthEndpoint := config.GetForwardAuthEndpoint()
	if forwardAuthEndpoint != "/forward" {
		t.Error("expected forward auth endpoint to be '/forward'")
	}

	oidc := config.GetOidc()
	if oidc {
		t.Error("expected oidc enabled to be false")
	}
}

func simpleServerConfiguration(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Secret: "5XyLSgKpo5kWrJqm",
				Cookies: Cookies{
					AuthName: "my_auth",
				},
				IntrospectScope:       "i:a",
				RevokeScope:           "r:b",
				SessionTimeoutSeconds: 4200,
				ForwardAuth: ForwardAuth{
					Endpoint:    "/fa",
					ExternalUrl: "http://forward.example.com",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
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

	sessionTimeout := config.GetSessionTimeoutSeconds()
	if sessionTimeout != 4200 {
		t.Error("expected session timeout to be 4200")
	}

	forwardAuthEnabled := config.GetForwardAuthEnabled()
	if !forwardAuthEnabled {
		t.Error("expected forward auth enabled to be true")
	}

	forwardAuthEndpoint := config.GetForwardAuthEndpoint()
	if forwardAuthEndpoint != "/fa" {
		t.Error("expected forward auth endpoint to be '/fa'")
	}
}

func emptyUIConfiguration(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			UI: UI{},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
	}

	footerText := config.GetFooterText()
	if footerText != "STOPnik" {
		t.Error("expected footer text to be 'STOPnik")
	}

	title := config.GetTitle()
	if title != "" {
		t.Error("expected title to be empty")
	}

	hideMascot := config.GetHideMascot()
	if hideMascot {
		t.Error("expected hideMascot to be false")
	}

	hideFooter := config.GetHideFooter()
	if hideFooter {
		t.Error("expected hideFooter to be false")
	}

	logoImage := config.GetLogoImage()
	if logoImage != nil {
		t.Error("expected logo image to be nil")
	}
}

func simpleUIConfiguration(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			UI: UI{
				HideFooter: true,
				HideLogo:   true,
				Title:      "Oh my Foo!",
				FooterText: "In the end",
				LogoImage:  "../../.test_files/test_logo.png",
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
	}

	footerText := config.GetFooterText()
	if footerText != "In the end" {
		t.Error("expected footer text be 'In the end'")
	}

	title := config.GetTitle()
	if title != "Oh my Foo!" {
		t.Error("expected title to be 'Oh my Foo!'")
	}

	hideMascot := config.GetHideMascot()
	if !hideMascot {
		t.Error("expected hideMascot to be true")
	}

	hideFooter := config.GetHideFooter()
	if !hideFooter {
		t.Error("expected hideFooter to be true")
	}

	logoImage := config.GetLogoImage()
	if logoImage == nil {
		t.Error("expected logo image to be non-nil")
	}
}

func validUsers(t *testing.T) {
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

	err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
	}

	if len(config.Users) != 3 {
		t.Errorf("expected 3 users, got %d", len(config.Users))
	}

	assertUserExistsWithName(t, "foo", config)
	assertUserExistsWithName(t, "bar", config)
	assertUserExistsWithName(t, "moo", config)
}

func invalidUsers(t *testing.T) {
	var invalidUserParameters = []User{
		{Username: "wrong", Password: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{Username: "empty", Password: ""},
		{Username: "", Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"}}

	for _, user := range invalidUserParameters {
		configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
			return make([]byte, 10), nil
		}, func(in []byte, out interface{}) (err error) {
			origin := out.(*Config)
			*origin = Config{
				Users: []User{user},
			}
			return nil
		})

		err := configLoader.LoadConfig("foo.txt")

		if err == nil {
			t.Error("expected error when loading config")
		}
	}
}

func validClients(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"http://localhost:8080/callback"},
				},
				{
					Id:           "bar",
					ClientSecret: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
					Redirects:    []string{"http://localhost:8080/callback", "https://example.com/callback"},
					AccessTTL:    20,
					RefreshTTL:   60,
					Issuer:       "other",
					Audience:     []string{"one", "two"},
				},
				{
					Id:           "moo",
					ClientSecret: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
					Redirects:    []string{"http://localhost:8080/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt")

	if err != nil {
		t.Error("did not expect error when loading config")
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
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

func invalidClients(t *testing.T) {
	var invalidClientParameters = []Client{
		{Id: "wrong", ClientSecret: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{Id: "empty", ClientSecret: ""},
		{Id: "", ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"},
		{Id: "no_redirects", ClientSecret: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"},
	}

	for _, client := range invalidClientParameters {
		configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
			return make([]byte, 10), nil
		}, func(in []byte, out interface{}) (err error) {
			origin := out.(*Config)
			*origin = Config{
				Clients: []Client{client},
			}
			return nil
		})

		err := configLoader.LoadConfig("foo.txt")

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
	if client.ClientSecret == "" {
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

	issuer := client.GetIssuer(&internalHttp.RequestData{})
	if issuer != expectedIssuer {
		t.Errorf("expected issuer to be '%s', got '%s'", expectedIssuer, issuer)
	}

	audience := client.GetAudience()
	if !reflect.DeepEqual(audience, expectedAudience) {
		t.Errorf("expected audience to be '%s', got '%s'", expectedAudience, audience)
	}
}
