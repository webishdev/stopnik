package config

import (
	"errors"
	"fmt"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"reflect"
	"testing"
)

type testExpectedClientValues struct {
	id                 string
	expectedAccessTTL  int
	expectedRefreshTTL int
	expectedIdTokenTTL int
	expectedIssuer     string
	expectedRolesClaim string
	expectedAudience   []string
}

type testExpectedUserValues struct {
	username                  string
	expectedPreferredUserName string
	expectedRoles             []string
}

func Test_DefaultValues(t *testing.T) {
	t.Run("Default value as string", func(t *testing.T) {
		assertDefaultValues[string](t, "abc", "def", GetOrDefaultString, func(a string) bool {
			return a == "abc"
		})

		assertDefaultValues[string](t, "", "def", GetOrDefaultString, func(a string) bool {
			return a == "def"
		})
	})

	t.Run("Default value as []string", func(t *testing.T) {
		assertDefaultValues[[]string](t, []string{"abc", "def"}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"abc", "def"})
		})

		assertDefaultValues[[]string](t, []string{}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"ghi", "jkl"})
		})
	})

	t.Run("Default value as int", func(t *testing.T) {
		assertDefaultValues[int](t, 22, 23, GetOrDefaultInt, func(a int) bool {
			return a == 22
		})

		assertDefaultValues[int](t, 0, 23, GetOrDefaultInt, func(a int) bool {
			return a == 23
		})
	})
}

func Test_ReadError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return nil, errors.New("test error")
	}, nil)

	err := configLoader.LoadConfig("foo.txt")

	if err == nil {
		t.Error("expected error")
	}
}

func Test_UnmarshalError(t *testing.T) {
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

func Test_EmptyServerConfiguration(t *testing.T) {
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

func Test_SimpleServerConfiguration(t *testing.T) {
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

func Test_EmptyUIConfiguration(t *testing.T) {
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

func Test_SimpleUIConfiguration(t *testing.T) {
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

func Test_ValidUsers(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Profile: UserProfile{
						PreferredUserName: "foofoo",
					},
					Roles: map[string][]string{
						"foo": {"Admin", "User"},
					},
				},
				{
					Username: "bar",
					Password: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
				},
				{
					Username: "moo",
					Password: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
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

	if len(config.Users) != 3 {
		t.Errorf("expected 3 users, got %d", len(config.Users))
	}

	assertUserExistsWithName(t, "foo", config)
	assertUserExistsWithName(t, "bar", config)
	assertUserExistsWithName(t, "moo", config)

	assertUserValues(t, config, "foo", testExpectedUserValues{
		username:                  "foo",
		expectedPreferredUserName: "foofoo",
		expectedRoles:             []string{"Admin", "User"},
	})
	assertUserValues(t, config, "bar", testExpectedUserValues{
		username:                  "bar",
		expectedPreferredUserName: "bar",
	})
	assertUserValues(t, config, "", testExpectedUserValues{
		username:                  "moo",
		expectedPreferredUserName: "moo",
	})
}

func Test_InvalidUsers(t *testing.T) {

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

func Test_ValidClients(t *testing.T) {
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
					IdTTL:        40,
					Issuer:       "other",
					RolesClaim:   "groups",
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

	assertClientValues(t, config, testExpectedClientValues{
		id:                 "foo",
		expectedAccessTTL:  5,
		expectedRefreshTTL: 0,
		expectedIdTokenTTL: 0,
		expectedRolesClaim: "roles",
		expectedIssuer:     "STOPnik",
		expectedAudience:   []string{"all"},
	})
	assertClientValues(t, config, testExpectedClientValues{
		id:                 "bar",
		expectedAccessTTL:  20,
		expectedRefreshTTL: 60,
		expectedIdTokenTTL: 40,
		expectedRolesClaim: "groups",
		expectedIssuer:     "other",
		expectedAudience:   []string{"one", "two"},
	})
}

func Test_InvalidClients(t *testing.T) {
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

func Test_ValidateRedirects(t *testing.T) {
	var validRedirects = []string{"http://foo.com/callback", "https://foo.com/callback", "https://foo.com/wildcard/*"}
	type redirectParameter struct {
		redirect       string
		expectedResult bool
	}

	var redirectParameters = []redirectParameter{
		{"http://foo.com/callback", true},
		{"https://foo.com/callback", true},
		{"https://foo.com/callback/more", false},
		{"https://foo.com/wildcard", false},
		{"https://foo.com/wildcard/", true},
		{"https://foo.com/wildcard/more", true},
	}

	for index, test := range redirectParameters {
		testMessage := fmt.Sprintf("Validate redirect %d %s", index, test.redirect)
		t.Run(testMessage, func(t *testing.T) {
			result, validationError := validateRedirect("fooId", validRedirects, test.redirect)
			if validationError != nil {
				t.Error("Validation should not return an error")
			}
			if result != test.expectedResult {
				t.Error("Redirect validation did not match")
			}
		})
	}
}

func Test_EmptyRedirect(t *testing.T) {
	var validRedirects = []string{"http://foo.com/callback", "https://foo.com/callback", "https://foo.com/wildcard/*"}
	result, validationError := validateRedirect("fooId", validRedirects, "")
	if validationError != nil {
		t.Error("Validation should not return an error")
	}
	if result {
		t.Error("Redirect validation did not match")
	}
}

func Test_NoRedirects(t *testing.T) {
	result, validationError := validateRedirect("fooId", []string{}, "http://foo.com/callback")
	if validationError != nil {
		t.Error("Validation should not return an error")
	}
	if result {
		t.Error("Redirect validation did not match")
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

func assertUserValues(t *testing.T, config *Config, clientId string, expected testExpectedUserValues) {
	user, exists := config.GetUser(expected.username)
	if !exists {
		t.Error("expected user")
	}
	if user.Username != expected.username {
		t.Error("expected correct username")
	}
	if user.Password == "" {
		t.Error("expected password")
	}
	if user.GetPreferredUsername() != expected.expectedPreferredUserName {
		t.Error("expected correct preferred username")
	}
	if clientId != "" {
		equal := reflect.DeepEqual(user.GetRoles(clientId), expected.expectedRoles)
		if !equal {
			t.Error("expected correct roles for user")
		}
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

func assertClientValues(t *testing.T, config *Config, expected testExpectedClientValues) {
	client, exits := config.GetClient(expected.id)
	if !exits {
		t.Errorf("expected client with id '%s' to exist", expected.id)
	}

	accessTTL := client.GetAccessTTL()
	if accessTTL != expected.expectedAccessTTL {
		t.Errorf("expected access TTL to be %d, got %d", expected.expectedAccessTTL, accessTTL)
	}

	refreshTTL := client.GetRefreshTTL()
	if refreshTTL != expected.expectedRefreshTTL {
		t.Errorf("expected refresh TTL to be %d, got %d", expected.expectedRefreshTTL, refreshTTL)
	}

	idTokenTTL := client.GetIdTTL()
	if idTokenTTL != expected.expectedIdTokenTTL {
		t.Errorf("expected id token TTL to be %d, got %d", expected.expectedIdTokenTTL, idTokenTTL)
	}

	issuer := client.GetIssuer(&internalHttp.RequestData{})
	if issuer != expected.expectedIssuer {
		t.Errorf("expected issuer to be '%s', got '%s'", expected.expectedIssuer, issuer)
	}

	audience := client.GetAudience()
	if !reflect.DeepEqual(audience, expected.expectedAudience) {
		t.Errorf("expected audience to be '%s', got '%s'", expected.expectedAudience, audience)
	}

	rolesClaim := client.GetRolesClaim()
	if rolesClaim != expected.expectedRolesClaim {
		t.Errorf("expected expectedRoles claim to be '%s', got '%s'", expected.expectedRolesClaim, rolesClaim)
	}

	validRedirect, validRedirectError := client.ValidateRedirect("http://localhost:8080/callback")
	if validRedirectError != nil {
		t.Error("expected valid redirect not return an error")
	}
	if !validRedirect {
		t.Error("expected valid redirect")
	}

	invalidRedirect, invalidRedirectError := client.ValidateRedirect("http://foo.com:8080/callback")
	if invalidRedirectError != nil {
		t.Error("expected invalid redirect not return an error")
	}
	if invalidRedirect {
		t.Error("did not expect redirect to be valid")
	}
}
