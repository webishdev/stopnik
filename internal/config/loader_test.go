package config

import (
	"errors"
	"github.com/BurntSushi/toml"
	"testing"
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

func Test_ReadConfigDoesNotActivate(t *testing.T) {
	initialConfig := &Config{Server: Server{Addr: ":8080"}}
	if initializationError := Initialize(initialConfig); initializationError != nil {
		t.Fatal(initializationError)
	}

	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return []byte(watcherTestConfig(":9090")), nil
	}, toml.Unmarshal)

	readConfig, readError := configLoader.ReadConfig("config.toml")
	if readError != nil {
		t.Fatal(readError)
	}

	if readConfig.Server.Addr != ":9090" {
		t.Errorf("expected read address, got %s", readConfig.Server.Addr)
	}

	if GetConfigInstance() != initialConfig {
		t.Error("ReadConfig should not change the current config")
	}

	Activate(readConfig)

	if GetConfigInstance() != readConfig {
		t.Error("Activate should change the current config")
	}
}

func Test_ReadConfigInvalid(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return []byte("[server]\naddr = \":8080\"\n"), nil
	}, toml.Unmarshal)

	_, readError := configLoader.ReadConfig("config.toml")
	if readError == nil {
		t.Error("expected error for invalid config")
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

[[clients]]
id = "foo"
accessTTL = 5
redirects = ["https://example.com/callback"]
grantTypes = ["authorization_code"]

[[users]]
username = "foo"
password = "bar"

[users.userProfile]
givenName = "John"

[users.userInformation.address]
postalCode = "12345"

[[classification]]
user = "foo"

[[classification.claims]]
name = "role"
values = ["a", "b"]
`
	config := &Config{}
	if decodeError := toml.Unmarshal([]byte(data), config); decodeError != nil {
		t.Fatal(decodeError)
	}

	if config.Server.Addr != ":8080" || config.Server.TLS.Keys.Cert != "server.crt" || config.Server.RevokeScope != "revoke" {
		t.Errorf("server not decoded as expected, %v", config.Server)
	}
	if config.Server.SecureCookie == nil || *config.Server.SecureCookie {
		t.Error("secure cookie should be decoded as false")
	}
	if len(config.Clients) != 1 || config.Clients[0].AccessTTL != 5 || config.Clients[0].GrantTypes[0] != "authorization_code" {
		t.Errorf("clients not decoded as expected, %v", config.Clients)
	}
	if len(config.Users) != 1 || config.Users[0].UserProfile.GivenName != "John" || config.Users[0].UserInformation.Address.PostalCode != "12345" {
		t.Errorf("users not decoded as expected, %v", config.Users)
	}
	if len(config.Classification) != 1 || len(config.Classification[0].Claims[0].Values) != 2 {
		t.Errorf("classification not decoded as expected, %v", config.Classification)
	}
}
