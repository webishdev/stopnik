package config

import (
	"fmt"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/system"
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
	expectedClientType oauth2.ClientType
}

type testExpectedUserValues struct {
	username                  string
	expectedName              string
	expectedPreferredUserName string
	expectedRoles             []string
	expectedAddress           string
}

func Test_ConfigNotInitialized(t *testing.T) {
	exitCode := 0
	newFunc := func(code int) {
		exitCode = code
	}
	system.ConfigureExit(newFunc)

	GetConfigInstance()

	if exitCode != 1 {
		t.Errorf("exit code should be 1")
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

	err := configLoader.LoadConfig("foo.txt", false)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
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

	forwardAuthCookieName := config.GetForwardAuthCookieName()
	if forwardAuthCookieName != "stopnik_forward_auth" {
		t.Error("expected forward auth cookie name to be 'stopnik_forward_auth'")
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

	forwardAuthParameterName := config.GetForwardAuthParameterName()
	if forwardAuthParameterName != "forward_id" {
		t.Error("expected forward auth parameter name to be 'forward_id'")
	}

	forwardAuthClient, exists := config.GetForwardAuthClient()
	if exists || forwardAuthClient != nil {
		t.Error("expected forward auth client to not exist")
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
				Issuer: "http://foo.com/bar",
				Cookies: Cookies{
					AuthName:        "my_auth",
					MessageName:     "my_message",
					ForwardAuthName: "my_forward_auth",
				},
				IntrospectScope:       "i:a",
				RevokeScope:           "r:b",
				SessionTimeoutSeconds: 4200,
				ForwardAuth: ForwardAuth{
					Endpoint:      "/fa",
					ExternalUrl:   "http://forward.example.com",
					ParameterName: "bla_blub",
					Redirects:     []string{"http://foo.example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
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

	issuer := config.GetIssuer(&internalHttp.RequestData{})
	if issuer != "http://foo.com/bar" {
		t.Error("expected issuer to be 'http://foo.com/bar'")
	}

	authCookieName := config.GetAuthCookieName()
	if authCookieName != "my_auth" {
		t.Error("expected auth cookie name to be 'my_auth'")
	}

	messageCookieName := config.GetMessageCookieName()
	if messageCookieName != "my_message" {
		t.Error("expected message cookie name to be 'my_message'")
	}

	forwardAuthCookieName := config.GetForwardAuthCookieName()
	if forwardAuthCookieName != "my_forward_auth" {
		t.Error("expected forward auth cookie name to be 'my_forward_auth'")
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

	forwardAuthParameterName := config.GetForwardAuthParameterName()
	if forwardAuthParameterName != "bla_blub" {
		t.Error("expected forward auth parameter name to be 'bla_blub'")
	}

	forwardAuthClient, exists := config.GetForwardAuthClient()
	if !exists || forwardAuthClient == nil {
		t.Error("expected forward auth client to exist")
	}

	if forwardAuthClient != nil {
		redirects := forwardAuthClient.Redirects
		reflect.DeepEqual(redirects, []string{"http://foo.example.com/callback"})
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

	err := configLoader.LoadConfig("foo.txt", false)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
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

	hideMascot := config.GetHideLogo()
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

	htmlTitle := config.GetHtmlTitle()
	if htmlTitle != "" {
		t.Error("expected html title to be empty")
	}

	invalidCredentialsMessage := config.GetInvalidCredentialsMessage()
	if invalidCredentialsMessage != "Invalid credentials" {
		t.Error("expected invalid credential message to be 'Invalid credentials'")
	}

	expiredLoginMessage := config.GetExpiredLoginMessage()
	if expiredLoginMessage != "Login expired, try again" {
		t.Error("expected invalid credential message to be 'Login expired, try again'")
	}
}

func Test_SimpleUIConfiguration(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			UI: UI{
				HideFooter:                true,
				HideLogo:                  true,
				Title:                     "Oh my Foo!",
				FooterText:                "In the end",
				LogoImage:                 "../../.test_files/test_logo.png",
				HtmlTitle:                 "My new title",
				InvalidCredentialsMessage: "Go away!",
				ExpiredLoginMessage:       "Time is up!",
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
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

	hideMascot := config.GetHideLogo()
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

	htmlTitle := config.GetHtmlTitle()
	if htmlTitle != "My new title" {
		t.Error("expected html title to be 'My new title'")
	}

	invalidCredentialsMessage := config.GetInvalidCredentialsMessage()
	if invalidCredentialsMessage != "Go away!" {
		t.Error("expected invalid credential message to be 'Go away!'")
	}

	expiredLoginMessage := config.GetExpiredLoginMessage()
	if expiredLoginMessage != "Time is up!" {
		t.Error("expected invalid credential message to be 'Time is up!'")
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
					UserProfile: UserProfile{
						PreferredUserName: "foofoo",
						GivenName:         "Hans",
						FamilyName:        "Mayer",
					},
					UserInformation: UserInformation{
						Address: &UserAddress{
							Street:     "Main Street 123",
							PostalCode: "98765",
							City:       "Maintown",
						},
					},
				},
				{
					Username: "bar",
					Password: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
					UserProfile: UserProfile{
						GivenName: "Hans",
					},
				},
				{
					Username: "moo",
					Password: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
				},
				{
					Username: "moo_more",
					Password: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
					UserProfile: UserProfile{
						FamilyName: "Mayer",
					},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
	}

	if len(config.Users) != 4 {
		t.Errorf("expected 3 users, got %d", len(config.Users))
	}

	assertUserExistsWithName(t, "foo", config)
	assertUserExistsWithName(t, "bar", config)
	assertUserExistsWithName(t, "moo", config)
	assertUserExistsWithName(t, "moo_more", config)

	assertUserValues(t, config, "foo", testExpectedUserValues{
		username:                  "foo",
		expectedName:              "Hans Mayer",
		expectedPreferredUserName: "foofoo",
		expectedRoles:             []string{"Admin", "User"},
		expectedAddress: `Main Street 123
98765
Maintown
`,
	})
	assertUserValues(t, config, "bar", testExpectedUserValues{
		username:                  "bar",
		expectedName:              "Hans",
		expectedPreferredUserName: "bar",
		expectedAddress:           "",
	})
	assertUserValues(t, config, "", testExpectedUserValues{
		username:                  "moo",
		expectedPreferredUserName: "moo",
		expectedAddress:           "",
	})
	assertUserValues(t, config, "", testExpectedUserValues{
		username:                  "moo_more",
		expectedName:              "Mayer",
		expectedPreferredUserName: "moo_more",
		expectedAddress:           "",
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

		err := configLoader.LoadConfig("foo.txt", true)

		if err == nil {
			t.Error("expected error when loading config")
		}

	}
}

func Test_DuplicateUsers(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
				{
					Username: "foo",
					Password: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err == nil {
		t.Error("expected error when loading config because of duplicate usernames")
	}
}

func Test_ValidClients(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Issuer: "other",
			},
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
					RolesClaim:   "groups",
					Audience:     []string{"one", "two"},
					Oidc:         true,
				},
				{
					Id:        "moo",
					Redirects: []string{"http://localhost:8080/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
	}

	config := GetConfigInstance()

	if config == nil {
		t.Fatal("config was nil")
	}

	if len(config.Clients) != 3 {
		t.Errorf("expected 3 clients, got %d", len(config.Clients))
	}

	oidc := config.GetOidc()
	if !oidc {
		t.Error("expected oidc to be true")
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
		expectedClientType: oauth2.CtConfidential,
	})
	assertClientValues(t, config, testExpectedClientValues{
		id:                 "bar",
		expectedAccessTTL:  20,
		expectedRefreshTTL: 60,
		expectedIdTokenTTL: 40,
		expectedRolesClaim: "groups",
		expectedIssuer:     "other",
		expectedAudience:   []string{"one", "two"},
		expectedClientType: oauth2.CtConfidential,
	})
	assertClientValues(t, config, testExpectedClientValues{
		id:                 "moo",
		expectedAccessTTL:  5,
		expectedRefreshTTL: 0,
		expectedIdTokenTTL: 0,
		expectedRolesClaim: "roles",
		expectedIssuer:     "STOPnik",
		expectedAudience:   []string{"all"},
		expectedClientType: oauth2.CtPublic,
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

		err := configLoader.LoadConfig("foo.txt", true)

		if err == nil {
			t.Error("expected error when loading config")
		}
	}
}

func Test_DuplicateClients(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Issuer: "other",
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"http://localhost:8080/callback"},
				},
				{
					Id:           "foo",
					ClientSecret: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
					Redirects:    []string{"http://localhost:8080/callback", "https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err == nil {
		t.Error("expected error when loading config because of duplicate client ids")
	}
}

func Test_NoClients(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
			},
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_NoUsers(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_UserWithoutPassword(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
			},
			Users: []User{
				{
					Username: "foo",
				},
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_UserWithoutUsername(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
			},
			Users: []User{
				{
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_ClientWithoutId(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
			},
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
			Clients: []Client{
				{
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_ClientWithoutRedirects(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
			},
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_TLSWithoutKey(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
				TLS: TLS{
					Addr: ":8443",
					Keys: Keys{
						Cert: "foo.crt",
					},
				},
			},
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_TLSWithoutCertificate(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
				TLS: TLS{
					Addr: ":8443",
					Keys: Keys{
						Key: "foo.key",
					},
				},
			},
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config")
	}
}

func Test_MinimalConfiguration(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr: ":8080",
				TLS: TLS{
					Addr: ":8443",
					Keys: Keys{
						Cert: "foo.crt",
						Key:  "foo.key",
					},
				},
			},
			Users: []User{
				{
					Username: "foo",
					Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				},
			},
			Clients: []Client{
				{
					Id:           "foo",
					ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
					Redirects:    []string{"https://example.com/callback"},
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err != nil {
		t.Errorf("did not expect error when loading config, %v", err)
	}
}

func Test_ValidateRedirects(t *testing.T) {
	var validRedirects = []string{"http://foo.com/callback", "https://foo.com/callback", "https://foo.com/wildcard/*", "https://bar.com", "https://moo.com/*", "https://moo.com:8080/*"}
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
		{"https://foo.com/wildcard/more", true},
		{"https://bar.com", true},
		{"https://bar.com/nope", false},
		{"https://moo.com", true},
		{"https://moo.com/", true},
		{"https://moo.com/sure", true},
		{"https://moo.com:9090/sure", false},
		{"https://moo.com:8080/sure", true},
		{"https://moo.com/sure?abc=def#hello_world", true},
		{"broken«ape`was~±here", false},
		{"", false},
	}

	for index, test := range redirectParameters {
		testMessage := fmt.Sprintf("Validate redirect %d %s", index, test.redirect)
		t.Run(testMessage, func(t *testing.T) {
			result := validateRedirect("fooId", validRedirects, test.redirect)
			if result != test.expectedResult {
				t.Error("Redirect validation did not match")
			}
		})
	}
}

func Test_EmptyRedirect(t *testing.T) {
	var validRedirects = []string{"http://foo.com/callback", "https://foo.com/callback", "https://foo.com/wildcard/*"}
	result := validateRedirect("fooId", validRedirects, "")
	if result {
		t.Error("Redirect validation did not match")
	}
}

func Test_NoRedirects(t *testing.T) {
	result := validateRedirect("fooId", []string{}, "http://foo.com/callback")
	if result {
		t.Error("Redirect validation did not match")
	}
}

func Test_RemoveLeadingSlash(t *testing.T) {
	type parameter struct {
		value          string
		expectedResult string
	}

	var parameters = []parameter{
		{value: "/foo", expectedResult: "foo"},
		{value: "foo", expectedResult: "foo"},
		{value: "/bar", expectedResult: "bar"},
		{value: "bar", expectedResult: "bar"},
	}

	for _, test := range parameters {
		testMessage := fmt.Sprintf("Remove leading slash from %s", test.value)
		t.Run(testMessage, func(t *testing.T) {
			result := removeLeadingSlash(test.value)
			if result != test.expectedResult {
				t.Error("Removing leading slash did not match")
			}
		})
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
	if expected.expectedName != user.GetName() {
		t.Errorf("expected correct name, got %v, expected %v", user.GetName(), expected.expectedName)
	}

	if user.GetFormattedAddress() != expected.expectedAddress {
		t.Errorf("expected correct address formatted for user, got %v, expected %v", user.GetFormattedAddress(), expected.expectedAddress)
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

	audience := client.GetAudience()
	if !reflect.DeepEqual(audience, expected.expectedAudience) {
		t.Errorf("expected audience to be '%s', got '%s'", expected.expectedAudience, audience)
	}

	rolesClaim := client.GetRolesClaim()
	if rolesClaim != expected.expectedRolesClaim {
		t.Errorf("expected expectedRoles claim to be '%s', got '%s'", expected.expectedRolesClaim, rolesClaim)
	}

	validRedirect := client.ValidateRedirect("http://localhost:8080/callback")
	if !validRedirect {
		t.Error("expected valid redirect")
	}

	invalidRedirect := client.ValidateRedirect("http://foo.com:8080/callback")
	if invalidRedirect {
		t.Error("did not expect redirect to be valid")
	}

	clientType := client.GetClientType()
	if clientType != expected.expectedClientType {
		t.Errorf("expected client type to be '%s', got '%s'", expected.expectedClientType, clientType)
	}
}
