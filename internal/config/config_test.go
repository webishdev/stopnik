package config

import (
	"fmt"
	"github.com/webishdev/stopnik/internal/oauth2"
	"github.com/webishdev/stopnik/internal/system"
	"reflect"
	"strings"
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

	if config.generatedSecret == "" || len(config.generatedSecret) != 32 {
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
					Enabled:       true,
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

	issuer := config.GetIssuer()
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

func Test_ForwardAuthMissingExternalUrl(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				ForwardAuth: ForwardAuth{
					Enabled: true,
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config because of empty external url in forward auth")
	}
}

func Test_SameCookieNameAuthAndMessage(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				Cookies: Cookies{
					AuthName:    "foo",
					MessageName: "foo",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config because of auth and message cookie with same name")
	}
}

func Test_SameCookieNameForwardAuthAndMessage(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				Cookies: Cookies{
					ForwardAuthName: "foo",
					MessageName:     "foo",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config because of forward auth and message cookie with same name")
	}
}

func Test_SameCookieNameForwardAuthAndAuth(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				Cookies: Cookies{
					ForwardAuthName: "foo",
					AuthName:        "foo",
				},
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err == nil {
		t.Error("expected error when loading config because of forward auth and auth cookie with same name")
	}
}

func Test_SimpleClassificationConfiguration(t *testing.T) {
	config := initializeTestEntries(t, Entries{
		Clients: []Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"http://localhost:8080/callback"},
			},
		},
		Users: []User{
			{
				Username: "bar",
				Password: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2",
			},
		},
		Classifications: []Classification{
			{
				User:   "bar",
				Client: "foo",
				Claims: []claim{
					{Name: "first_claim", Value: "fist_value"},
				},
			},
			{
				User:   "bar",
				Users:  []string{"bar"},
				Client: "foo",
				Scope:  "main:scope",
				Claims: []claim{
					{Name: "second_claim", Value: "second_value", Scope: "claim:scope"},
				},
			},
			{
				User:   "bar",
				Client: "foo",
				Claims: []claim{
					{Name: "third_claim", Values: []string{"third_value1", "third_value2"}, Scope: "other:scope"},
				},
			},
		},
	})

	claims := config.GetClaims("bar", "foo", []string{})

	if len(claims) != 1 {
		t.Error("expected claim to exists")
	}

	if (*claims[0]).GetName() != "first_claim" {
		t.Error("expected first_claim claim")
	}

	if !reflect.DeepEqual((*claims[0]).GetValues(), "fist_value") {
		t.Error("expected first_claim to have correct values")
	}

	claims = config.GetClaims("abc", "foo", []string{})

	if len(claims) != 0 {
		t.Error("expected claim not to exists")
	}

	claims = config.GetClaims("bar", "foo", []string{"main:scope"})

	if len(claims) != 1 {
		t.Error("expected claim to exists")
	}

	if (*claims[0]).GetName() != "first_claim" {
		t.Error("expected first_claim claim")
	}

	claims = config.GetClaims("bar", "foo", []string{"claim:scope"})

	if len(claims) != 1 {
		t.Error("expected claim to exists")
	}

	if (*claims[0]).GetName() != "first_claim" {
		t.Error("expected first_claim claim")
	}

	claims = config.GetClaims("bar", "foo", []string{"main:scope", "claim:scope"})

	if len(claims) != 2 {
		t.Error("expected both claims to exists")
	}

	if (*claims[0]).GetName() != "first_claim" {
		t.Error("expected first_claim claim")
	}

	if (*claims[1]).GetName() != "second_claim" {
		t.Error("expected second_claim claim")
	}

	claims = config.GetClaims("bar", "foo", []string{"other:scope"})

	if len(claims) != 2 {
		t.Error("expected both claims to exists")
	}

	if (*claims[0]).GetName() != "first_claim" {
		t.Error("expected first_claim claim")
	}

	if (*claims[1]).GetName() != "third_claim" {
		t.Error("expected third_claim claim")
	}

	if !reflect.DeepEqual((*claims[1]).GetValues(), []string{"third_value1", "third_value2"}) {
		t.Error("expected third_claim to have correct values")
	}
}

func Test_InvalidClassifications(t *testing.T) {
	type classificationParameter struct {
		name   string
		claims []claim
	}

	var classificationParameters = []classificationParameter{
		{"Empty claim name", []claim{{Value: "first_name"}}},
		{"Empty claim values", []claim{{Name: "first_name"}}},
		{"Both claim values", []claim{{Name: "first_name", Value: "foo", Values: []string{"bar"}}}},
	}

	for _, test := range classificationParameters {
		t.Run(test.name, func(t *testing.T) {
			classification := &Classification{User: "bar", Client: "foo", Claims: test.claims}
			if validationError := ValidateClassification(classification); validationError == nil {
				t.Error("expected classification to be invalid")
			}
		})
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
	users := []User{
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
	}

	for _, user := range users {
		if validationError := ValidateUser(&user); validationError != nil {
			t.Errorf("did not expect user %s to be invalid, %v", user.Username, validationError)
		}
	}

	config := initializeTestEntries(t, Entries{Users: users})

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
		{Username: "foo"},
		{Username: "", Password: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181"}}

	for _, user := range invalidUserParameters {
		if validationError := ValidateUser(&user); validationError == nil {
			t.Errorf("expected user '%s' to be invalid", user.Username)
		}
	}
}

func Test_DuplicateUsers(t *testing.T) {
	config := initializeTestEntries(t, Entries{})

	applyError := config.ApplyEntries(Entries{
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
	})

	if applyError == nil {
		t.Error("expected error when applying entries because of duplicate usernames")
	}
}

func Test_ValidClients(t *testing.T) {
	clients := []Client{
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
			Audience:     []string{"one", "two"},
			Oidc:         true,
		},
		{
			Id:        "moo",
			Redirects: []string{"http://localhost:8080/callback"},
		},
	}

	for _, client := range clients {
		if validationError := ValidateClient(&client); validationError != nil {
			t.Errorf("did not expect client %s to be invalid, %v", client.Id, validationError)
		}
	}

	config := initializeTestEntries(t, Entries{Clients: clients})

	if len(config.GetClients()) != 3 {
		t.Errorf("expected 3 clients, got %d", len(config.GetClients()))
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
		{Id: "", ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181", Redirects: []string{"https://example.com/callback"}},
		{Id: "no_redirects", ClientSecret: "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"},
		{Id: "unknown_grant", Redirects: []string{"https://example.com/callback"}, GrantTypes: []string{"foo"}},
	}

	for _, client := range invalidClientParameters {
		if validationError := ValidateClient(&client); validationError == nil {
			t.Errorf("expected client '%s' to be invalid", client.Id)
		}
	}
}

func Test_DuplicateClients(t *testing.T) {
	config := initializeTestEntries(t, Entries{})

	applyError := config.ApplyEntries(Entries{
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
	})

	if applyError == nil {
		t.Error("expected error when applying entries because of duplicate client ids")
	}
}

func Test_NoDynamicEntries(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
			},
		}
		return nil
	})

	err := configLoader.LoadConfig("foo.txt", true)

	if err != nil {
		t.Errorf("did not expect error when loading static config without clients and users, %v", err)
	}

	config := GetConfigInstance()
	if len(config.GetClients()) != 0 || config.GetOidc() {
		t.Error("expected no clients")
	}
	if _, exists := config.GetUser("foo"); exists {
		t.Error("expected no users")
	}
}

func Test_TLSWithoutKey(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		origin := out.(*Config)
		*origin = Config{
			Server: Server{
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				TLS: TLS{
					Addr: ":8443",
					Keys: Keys{
						Cert: "foo.crt",
					},
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
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				TLS: TLS{
					Addr: ":8443",
					Keys: Keys{
						Key: "foo.key",
					},
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
				Addr:   ":8080",
				Issuer: "https://auth.example.com",
				TLS: TLS{
					Addr: ":8443",
					Keys: Keys{
						Cert: "foo.crt",
						Key:  "foo.key",
					},
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

func Test_DynamicDirectories(t *testing.T) {
	type dirParameter struct {
		name                    string
		configDir               string
		expectedStaticFile      string
		expectedClients         string
		expectedUsers           string
		expectedClassifications string
	}

	var dirParameters = []dirParameter{
		{"Relative", ".config/default", ".config/default/config.toml", ".config/default/client.d", ".config/default/user.d", ".config/default/classification.d"},
		{"Absolute", "/etc/stopnik", "/etc/stopnik/config.toml", "/etc/stopnik/client.d", "/etc/stopnik/user.d", "/etc/stopnik/classification.d"},
	}

	for _, test := range dirParameters {
		t.Run(test.name, func(t *testing.T) {
			var readFile string
			configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
				readFile = filename
				return make([]byte, 10), nil
			}, func(in []byte, out interface{}) (err error) {
				origin := out.(*Config)
				*origin = Config{Server: Server{Addr: ":8080", Issuer: "https://auth.example.com"}}
				return nil
			})

			if loadError := configLoader.LoadConfig(test.configDir, true); loadError != nil {
				t.Fatal(loadError)
			}

			if readFile != test.expectedStaticFile {
				t.Errorf("static file %s did not match %s", readFile, test.expectedStaticFile)
			}

			config := GetConfigInstance()
			if config.GetClientsDir() != test.expectedClients {
				t.Errorf("clients dir %s did not match %s", config.GetClientsDir(), test.expectedClients)
			}
			if config.GetUsersDir() != test.expectedUsers {
				t.Errorf("users dir %s did not match %s", config.GetUsersDir(), test.expectedUsers)
			}
			if config.GetClassificationsDir() != test.expectedClassifications {
				t.Errorf("classifications dir %s did not match %s", config.GetClassificationsDir(), test.expectedClassifications)
			}
		})
	}
}

func initializeTestEntries(t *testing.T, entries Entries) *Config {
	t.Helper()
	config := &Config{Server: Server{Issuer: "other"}}
	if initializationError := Initialize(config); initializationError != nil {
		t.Fatal(initializationError)
	}
	if applyError := config.ApplyEntries(entries); applyError != nil {
		t.Fatal(applyError)
	}
	return config
}

func Test_ValidateRedirects(t *testing.T) {
	client := &Client{
		Id: "fooId",
		Redirects: []string{
			"http://foo.com/callback",
			"https://foo.com/callback",
			"https://bar.com",
			"https://query.com/callback?tenant=a",
			"http://127.0.0.1/callback",
			"http://[::1]:7000/callback",
			"http://localhost:8080/callback",
		},
	}
	type redirectParameter struct {
		redirect       string
		expectedResult bool
	}

	var redirectParameters = []redirectParameter{
		{"http://foo.com/callback", true},
		{"https://foo.com/callback", true},
		{"https://bar.com", true},
		{"https://query.com/callback?tenant=a", true},
		{"https://foo.com/callback/more", false},
		{"https://foo.com/callback?foo=bar", false},
		{"https://query.com/callback?tenant=a&foo=bar", false},
		{"https://query.com/callback", false},
		{"https://foo.com/Callback", false},
		{"https://foo.com/callback/", false},
		{"https://bar.com/", false},
		{"https://foo.com/callback#fragment", false},
		{"https://foo.com/callback#", false},
		{"https://user@foo.com/callback", false},
		{"https://user:password@foo.com/callback", false},
		{"https://foo.com:8443/callback", false},
		{"http://127.0.0.1/callback", true},
		{"http://127.0.0.1:51004/callback", true},
		{"http://127.0.0.1:51004/other", false},
		{"http://127.0.0.1:51004/callback?foo=bar", false},
		{"https://127.0.0.1:51004/callback", false},
		{"http://[::1]:51004/callback", true},
		{"http://localhost:8080/callback", true},
		{"http://localhost:51004/callback", false},
		{"/callback", false},
		{"foo.com/callback", false},
		{"broken«ape`was~±here", false},
		{"", false},
	}

	for index, test := range redirectParameters {
		testMessage := fmt.Sprintf("Validate redirect %d %s", index, test.redirect)
		t.Run(testMessage, func(t *testing.T) {
			result := client.ValidateRedirect(test.redirect)
			if result != test.expectedResult {
				t.Error("Redirect validation did not match")
			}
		})
	}
}

func Test_ValidateRedirectsWildcardIgnoredForRegularClient(t *testing.T) {
	client := &Client{Id: "fooId", Redirects: []string{"https://app.example/cb*", "https://moo.com/*"}}

	for _, redirect := range []string{"https://app.example/cb", "https://app.example/cbevil", "https://app.example/cb/../anything", "https://moo.com/sure"} {
		if client.ValidateRedirect(redirect) {
			t.Errorf("did not expect redirect %s to be valid for a regular client", redirect)
		}
	}
}

func Test_ValidateForwardAuthRedirects(t *testing.T) {
	client := &Client{
		Id:            "forwardId",
		isForwardAuth: true,
		Redirects:     []string{"https://foo.com/app/*", "https://moo.com/*", "https://moo.com:8080/*", "https://bar.com/cb*", "https://exact.com/page"},
	}
	type redirectParameter struct {
		redirect       string
		expectedResult bool
	}

	var redirectParameters = []redirectParameter{
		{"https://foo.com/app/page?x=1", true},
		{"https://foo.com/app/", true},
		{"https://foo.com/app/deep/page?forward_id=abc", true},
		{"https://foo.com/app", false},
		{"https://foo.com/application", false},
		{"https://foo.com/app/../admin", false},
		{"https://foo.com/app/./admin", false},
		{"https://foo.com/app/%2e%2e/admin", false},
		{"https://foo.com/app/%2E%2E/admin", false},
		{"https://foo.com/app/..%2fadmin", false},
		{"https://foo.com/app/..%2Fadmin", false},
		{"https://foo.com/app/..\\admin", false},
		{"https://foo.com/app/page#fragment", false},
		{"https://user@foo.com/app/page", false},
		{"http://foo.com/app/page", false},
		{"https://evil.com/app/page", false},
		{"https://moo.com", true},
		{"https://moo.com/", true},
		{"https://moo.com/sure", true},
		{"https://moo.com:9090/sure", false},
		{"https://moo.com:8080/sure", true},
		{"https://bar.com/cb", true},
		{"https://bar.com/cb/more", true},
		{"https://bar.com/cbevil", false},
		{"https://exact.com/page?forward_id=abc", true},
		{"https://exact.com/page/more", false},
		{"", false},
	}

	for index, test := range redirectParameters {
		testMessage := fmt.Sprintf("Validate forward auth redirect %d %s", index, test.redirect)
		t.Run(testMessage, func(t *testing.T) {
			result := client.ValidateRedirect(test.redirect)
			if result != test.expectedResult {
				t.Error("Redirect validation did not match")
			}
		})
	}
}

func Test_NoRedirects(t *testing.T) {
	client := &Client{Id: "fooId"}
	result := client.ValidateRedirect("http://foo.com/callback")
	if result {
		t.Error("Redirect validation did not match")
	}
}

func Test_InvalidConfiguredRedirects(t *testing.T) {
	var invalidRedirects = []string{
		"https://example.com/callback*",
		"https://example.com/*",
		"https://example.com/callback#fragment",
		"https://user@example.com/callback",
		"/callback",
		"example.com/callback",
		"broken«ape`was~±here",
	}

	for _, redirect := range invalidRedirects {
		t.Run(redirect, func(t *testing.T) {
			client := &Client{Id: "foo", Redirects: []string{"https://example.com/valid", redirect}}
			validationError := ValidateClient(client)
			if validationError == nil {
				t.Fatalf("expected client with redirect %s to be invalid", redirect)
			}
			if !strings.Contains(validationError.Error(), "foo") || !strings.Contains(validationError.Error(), redirect) {
				t.Errorf("expected error to name the client and the redirect, got %v", validationError)
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

func Test_GetDisallowedScopes(t *testing.T) {
	testConfig := &Config{
		Server: Server{
			IntrospectScope: "custom:introspect",
		},
	}

	type scopeParameter struct {
		name     string
		client   Client
		scopes   []string
		expected []string
	}

	var scopeParameters = []scopeParameter{
		{"No scopes allowed by default", Client{}, []string{"", "openid", "foo:bar"}, []string{"openid", "foo:bar"}},
		{"Empty scope is ignored", Client{}, []string{""}, nil},
		{"Reserved scopes not allowed by default", Client{}, []string{"stopnik:revoke", "stopnik:other", "custom:introspect"}, []string{"stopnik:revoke", "stopnik:other", "custom:introspect"}},
		{"OpenId Connect scopes allowed by default for OpenId Connect client", Client{Oidc: true}, []string{"openid", "profile", "email", "address", "phone", "offline_access"}, nil},
		{"Custom scope not allowed by default for OpenId Connect client", Client{Oidc: true}, []string{"openid", "foo:bar", "stopnik:revoke"}, []string{"foo:bar", "stopnik:revoke"}},
		{"Forward auth scope allowed by default for forward auth client", Client{isForwardAuth: true}, []string{"forward:auth"}, nil},
		{"Other scopes not allowed by default for forward auth client", Client{isForwardAuth: true}, []string{"forward:auth", "openid"}, []string{"openid"}},
		{"Forward auth scope not allowed by default for regular client", Client{Oidc: true}, []string{"forward:auth"}, []string{"forward:auth"}},
		{"Only configured scopes allowed", Client{Scopes: []string{"openid", "stopnik:introspect"}}, []string{"openid", "stopnik:introspect", "foo:bar"}, []string{"foo:bar"}},
		{"Configured scopes replace default scopes", Client{Oidc: true, Scopes: []string{"openid"}}, []string{"openid", "profile"}, []string{"profile"}},
	}

	for _, test := range scopeParameters {
		t.Run(test.name, func(t *testing.T) {
			disallowedScopes := testConfig.GetDisallowedScopes(&test.client, test.scopes)
			if !reflect.DeepEqual(disallowedScopes, test.expected) {
				t.Errorf("disallowed scopes %v did not match %v", disallowedScopes, test.expected)
			}
		})
	}
}

func Test_IsGrantTypeAllowed(t *testing.T) {
	type grantTypeParameter struct {
		name      string
		client    Client
		grantType oauth2.GrantType
		expected  bool
	}

	var grantTypeParameters = []grantTypeParameter{
		{"Authorization code allowed by default", Client{ClientSecret: "abc"}, oauth2.GtAuthorizationCode, true},
		{"Refresh token allowed by default", Client{ClientSecret: "abc"}, oauth2.GtRefreshToken, true},
		{"Authorization code allowed by default for public client", Client{}, oauth2.GtAuthorizationCode, true},
		{"Password not allowed by default", Client{ClientSecret: "abc"}, oauth2.GtPassword, false},
		{"Implicit not allowed by default", Client{ClientSecret: "abc"}, oauth2.GtImplicit, false},
		{"Client credentials not allowed by default", Client{ClientSecret: "abc"}, oauth2.GtClientCredentials, false},
		{"Client credentials allowed for confidential client when configured", Client{ClientSecret: "abc", GrantTypes: []string{"client_credentials"}}, oauth2.GtClientCredentials, true},
		{"Client credentials not allowed for public client", Client{GrantTypes: []string{"client_credentials"}}, oauth2.GtClientCredentials, false},
		{"Password allowed when configured", Client{GrantTypes: []string{"password"}}, oauth2.GtPassword, true},
		{"Only configured grant types allowed", Client{GrantTypes: []string{"authorization_code"}}, oauth2.GtPassword, false},
		{"Refresh token not allowed when not configured", Client{GrantTypes: []string{"authorization_code"}}, oauth2.GtRefreshToken, false},
		{"Configured grant types are case insensitive", Client{GrantTypes: []string{"Authorization_Code"}}, oauth2.GtAuthorizationCode, true},
	}

	for _, test := range grantTypeParameters {
		t.Run(test.name, func(t *testing.T) {
			if allowed := test.client.IsGrantTypeAllowed(test.grantType); allowed != test.expected {
				t.Errorf("result %t did not match %t", allowed, test.expected)
			}
		})
	}
}

func Test_GetSupportedGrantAndResponseTypes(t *testing.T) {
	type supportedParameter struct {
		name                  string
		clients               []Client
		expectedGrantTypes    []oauth2.GrantType
		expectedResponseTypes []oauth2.ResponseType
	}

	var supportedParameters = []supportedParameter{
		{"No clients", nil, nil, nil},
		{
			"Default client",
			[]Client{{Id: "foo", Redirects: []string{"https://example.com/callback"}}},
			[]oauth2.GrantType{oauth2.GtAuthorizationCode, oauth2.GtRefreshToken},
			[]oauth2.ResponseType{oauth2.RtCode},
		},
		{
			"Union of all clients",
			[]Client{
				{Id: "foo", Redirects: []string{"https://example.com/callback"}},
				{Id: "bar", ClientSecret: "abc", GrantTypes: []string{"client_credentials"}},
				{Id: "moo", GrantTypes: []string{"implicit", "client_credentials"}},
			},
			[]oauth2.GrantType{oauth2.GtAuthorizationCode, oauth2.GtClientCredentials, oauth2.GtRefreshToken, oauth2.GtImplicit},
			[]oauth2.ResponseType{oauth2.RtCode, oauth2.RtToken},
		},
		{
			"Client credentials only for confidential client",
			[]Client{{Id: "moo", GrantTypes: []string{"password", "client_credentials"}}},
			[]oauth2.GrantType{oauth2.GtPassword},
			nil,
		},
	}

	for _, test := range supportedParameters {
		t.Run(test.name, func(t *testing.T) {
			testConfig := initializeTestEntries(t, Entries{Clients: test.clients})
			if supportedGrantTypes := testConfig.GetSupportedGrantTypes(); !reflect.DeepEqual(supportedGrantTypes, test.expectedGrantTypes) {
				t.Errorf("supported grant types %v did not match %v", supportedGrantTypes, test.expectedGrantTypes)
			}
			if supportedResponseTypes := testConfig.GetSupportedResponseTypes(); !reflect.DeepEqual(supportedResponseTypes, test.expectedResponseTypes) {
				t.Errorf("supported response types %v did not match %v", supportedResponseTypes, test.expectedResponseTypes)
			}
		})
	}
}

func Test_GetSecureCookie(t *testing.T) {
	secure := true
	insecure := false

	type secureCookieParameter struct {
		name         string
		secureCookie *bool
		expected     bool
	}

	var secureCookieParameters = []secureCookieParameter{
		{"Secure by default", nil, true},
		{"Secure configured", &secure, true},
		{"Insecure configured", &insecure, false},
	}

	for _, test := range secureCookieParameters {
		t.Run(test.name, func(t *testing.T) {
			testConfig := &Config{Server: Server{SecureCookie: test.secureCookie}}
			if result := testConfig.GetSecureCookie(); result != test.expected {
				t.Errorf("result %t did not match %t", result, test.expected)
			}
		})
	}
}

func Test_GetBasePath(t *testing.T) {
	type basePathParameter struct {
		basePath           string
		expectedBasePath   string
		expectedCookiePath string
	}

	var basePathParameters = []basePathParameter{
		{"", "", "/"},
		{"/", "", "/"},
		{"/auth", "/auth", "/auth"},
		{"auth", "/auth", "/auth"},
		{"/auth/", "/auth", "/auth"},
		{"/foo/bar", "/foo/bar", "/foo/bar"},
	}

	for _, test := range basePathParameters {
		testMessage := fmt.Sprintf("Base path '%s'", test.basePath)
		t.Run(testMessage, func(t *testing.T) {
			testConfig := &Config{Server: Server{BasePath: test.basePath}}
			if result := testConfig.GetBasePath(); result != test.expectedBasePath {
				t.Errorf("base path %s did not match %s", result, test.expectedBasePath)
			}
			if result := testConfig.GetCookiePath(); result != test.expectedCookiePath {
				t.Errorf("cookie path %s did not match %s", result, test.expectedCookiePath)
			}
		})
	}
}

func Test_ValidateBasePath(t *testing.T) {
	type basePathParameter struct {
		basePath string
		valid    bool
	}

	var basePathParameters = []basePathParameter{
		{"", true},
		{"/", true},
		{"/auth", true},
		{"/foo/bar/", true},
		{"/auth?foo=bar", false},
		{"/auth#foo", false},
		{"//example.com", false},
		{"http://example.com/auth", false},
		{"/foo bar", false},
		{"/foo\\bar", false},
	}

	for _, test := range basePathParameters {
		testMessage := fmt.Sprintf("Base path '%s'", test.basePath)
		t.Run(testMessage, func(t *testing.T) {
			if result := isValidBasePath(test.basePath); result != test.valid {
				t.Errorf("result %t did not match %t", result, test.valid)
			}
			if !test.valid {
				testConfig := &Config{Server: Server{Addr: ":8080", Issuer: "https://auth.example.com", BasePath: test.basePath}}
				if validationError := testConfig.Validate(); validationError == nil {
					t.Error("expected validation error for invalid base path")
				}
			}
		})
	}
}

func Test_GetEndpointURL(t *testing.T) {
	type endpointParameter struct {
		name        string
		basePath    string
		issuer      string
		expectedURL string
	}

	var endpointParameters = []endpointParameter{
		{"No base path", "", "https://auth.example.com", "https://auth.example.com/token"},
		{"No base path, issuer with trailing slash", "", "https://auth.example.com/", "https://auth.example.com/token"},
		{"Issuer ends with base path", "/auth", "https://example.com/auth", "https://example.com/auth/token"},
		{"Issuer ends with base path and trailing slash", "/auth", "https://example.com/auth/", "https://example.com/auth/token"},
		{"Issuer without base path", "/auth", "https://auth.example.com", "https://auth.example.com/auth/token"},
		{"Issuer with other path", "/auth", "https://example.com/stopnik", "https://example.com/stopnik/auth/token"},
	}

	for _, test := range endpointParameters {
		t.Run(test.name, func(t *testing.T) {
			testConfig := &Config{Server: Server{BasePath: test.basePath, Issuer: test.issuer}}
			if issuer := testConfig.GetIssuer(); issuer != test.issuer {
				t.Errorf("issuer %s did not match %s", issuer, test.issuer)
			}
			endpointURL, endpointURLError := testConfig.GetEndpointURL("/token")
			if endpointURLError != nil {
				t.Fatal(endpointURLError)
			}
			if endpointURL != test.expectedURL {
				t.Errorf("endpoint URL %s did not match %s", endpointURL, test.expectedURL)
			}
		})
	}
}

func Test_ValidateIssuer(t *testing.T) {
	type issuerParameter struct {
		issuer string
		valid  bool
	}

	var issuerParameters = []issuerParameter{
		{"https://auth.example.com", true},
		{"https://example.com/auth", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:8080", true},
		{"http://auth.example.com", true},
		{"", false},
		{"auth.example.com", false},
		{"/auth", false},
		{"https://auth.example.com?foo=bar", false},
		{"https://auth.example.com?", false},
		{"https://auth.example.com#foo", false},
		{"https://user@auth.example.com", false},
		{"ftp://auth.example.com", false},
		{"broken«ape`was~±here", false},
	}

	for _, test := range issuerParameters {
		testMessage := fmt.Sprintf("Issuer '%s'", test.issuer)
		t.Run(testMessage, func(t *testing.T) {
			testConfig := &Config{Server: Server{Addr: ":8080", Issuer: test.issuer}}
			validationError := testConfig.Validate()
			if test.valid && validationError != nil {
				t.Errorf("did not expect validation error, %v", validationError)
			}
			if !test.valid && validationError == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func Test_TrustedProxies(t *testing.T) {
	validConfig := &Config{Server: Server{Addr: ":8080", Issuer: "https://auth.example.com", TrustedProxies: []string{"10.0.0.0/8", "192.0.2.1", "::1"}}}
	if validationError := validConfig.Validate(); validationError != nil {
		t.Fatalf("did not expect validation error, %v", validationError)
	}
	if initializationError := Initialize(validConfig); initializationError != nil {
		t.Fatal(initializationError)
	}
	trustedProxies := validConfig.GetTrustedProxies()
	if len(trustedProxies) != 3 || trustedProxies[0].String() != "10.0.0.0/8" || trustedProxies[1].String() != "192.0.2.1/32" {
		t.Errorf("unexpected trusted proxies %v", trustedProxies)
	}

	invalidConfig := &Config{Server: Server{Addr: ":8080", Issuer: "https://auth.example.com", TrustedProxies: []string{"10.0.0.0/8", "proxy.example.com"}}}
	if validationError := invalidConfig.Validate(); validationError == nil {
		t.Error("expected validation error for invalid trusted proxy")
	}
}

func Test_GetRequirePkce(t *testing.T) {
	required := true
	notRequired := false

	type pkceParameter struct {
		name     string
		client   Client
		expected bool
	}

	var pkceParameters = []pkceParameter{
		{"Required by default for confidential client", Client{ClientSecret: "abc"}, true},
		{"Required when configured", Client{ClientSecret: "abc", RequirePkce: &required}, true},
		{"Not required when disabled for confidential client", Client{ClientSecret: "abc", RequirePkce: &notRequired}, false},
		{"Always required for public client", Client{RequirePkce: &notRequired}, true},
	}

	for _, test := range pkceParameters {
		t.Run(test.name, func(t *testing.T) {
			if result := test.client.GetRequirePkce(); result != test.expected {
				t.Errorf("result %t did not match %t", result, test.expected)
			}
		})
	}
}
