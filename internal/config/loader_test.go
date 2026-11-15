package config

import (
	"errors"
	"github.com/BurntSushi/toml"
	"testing"
	"time"
)

func Test_ReadError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return nil, errors.New("test error")
	}, nil)

	err := configLoader.LoadConfig("foo.txt", false)

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

	err := configLoader.LoadConfig("foo.txt", false)

	if err == nil {
		t.Error("expected error")
	}
}

func Test_TOMLConfig(t *testing.T) {
	data := `
[server]
addr = ":8080"
secureCookie = false
revokeScopeScope = "revoke"

[server.tls]
addr = ":8081"

[server.tls.keys]
cert = "server.crt"
key = "server.key"

[dynamic]
watch = true
interval = 5
clients = "/clients"
`
	config := &Config{}
	if decodeError := toml.Unmarshal([]byte(data), config); decodeError != nil {
		t.Fatal(decodeError)
	}

	// the deprecated revokeScopeScope is still accepted
	if config.Server.Addr != ":8080" || config.Server.TLS.Keys.Cert != "server.crt" || config.GetRevokeScope() != "revoke" {
		t.Errorf("server not decoded as expected, %v", config.Server)
	}
	if config.Server.SecureCookie == nil || *config.Server.SecureCookie {
		t.Error("secure cookie should be decoded as false")
	}
	if !config.Dynamic.Watch || config.GetDynamicInterval() != 5*time.Second {
		t.Errorf("dynamic not decoded as expected, %v", config.Dynamic)
	}
}

func Test_TOMLEntries(t *testing.T) {
	client := &Client{}
	clientData := `
id = "foo"
accessTTL = 5
redirects = ["https://example.com/callback"]
grantTypes = ["authorization_code"]
`
	if decodeError := toml.Unmarshal([]byte(clientData), client); decodeError != nil {
		t.Fatal(decodeError)
	}
	if client.Id != "foo" || client.AccessTTL != 5 || client.GrantTypes[0] != "authorization_code" {
		t.Errorf("client not decoded as expected, %v", client)
	}

	user := &User{}
	userData := `
username = "foo"
password = "bar"

[userProfile]
givenName = "John"

[userInformation.address]
postalCode = "12345"
`
	if decodeError := toml.Unmarshal([]byte(userData), user); decodeError != nil {
		t.Fatal(decodeError)
	}
	if user.Username != "foo" || user.UserProfile.GivenName != "John" || user.UserInformation.Address.PostalCode != "12345" {
		t.Errorf("user not decoded as expected, %v", user)
	}

	classification := &Classification{}
	classificationData := `
user = "foo"

[[claims]]
name = "role"
values = ["a", "b"]
`
	if decodeError := toml.Unmarshal([]byte(classificationData), classification); decodeError != nil {
		t.Fatal(decodeError)
	}
	if classification.User != "foo" || len(classification.Claims[0].Values) != 2 {
		t.Errorf("classification not decoded as expected, %v", classification)
	}
}

func Test_TOMLConfigRevokeScope(t *testing.T) {
	type revokeScopeParameter struct {
		name     string
		data     string
		expected string
	}

	var revokeScopeParameters = []revokeScopeParameter{
		{"Default", "[server]\n", "stopnik:revoke"},
		{"Revoke scope", "[server]\nrevokeScope = \"new\"\n", "new"},
		{"Deprecated revoke scope", "[server]\nrevokeScopeScope = \"old\"\n", "old"},
		{"Revoke scope wins over deprecated", "[server]\nrevokeScope = \"new\"\nrevokeScopeScope = \"old\"\n", "new"},
	}

	for _, test := range revokeScopeParameters {
		t.Run(test.name, func(t *testing.T) {
			config := &Config{}
			if decodeError := toml.Unmarshal([]byte(test.data), config); decodeError != nil {
				t.Fatal(decodeError)
			}
			if revokeScope := config.GetRevokeScope(); revokeScope != test.expected {
				t.Errorf("revoke scope %s did not match %s", revokeScope, test.expected)
			}
		})
	}
}
