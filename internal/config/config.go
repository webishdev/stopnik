package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"math/rand"
	"os"
	"stopnik/log"
	"time"
)

type TLS struct {
	Port int    `yaml:"port"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Server struct {
	Port            int    `yaml:"port"`
	AuthCookieName  string `yaml:"authCookieName"`
	Secret          string `yaml:"secret"`
	TLS             TLS    `yaml:"tls"`
	LogoutRedirect  string `yaml:"logoutRedirect"`
	IntrospectScope string `yaml:"introspectScope"`
}

type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Client struct {
	Id         string   `yaml:"id"`
	Secret     string   `yaml:"secret"`
	ClientType string   `yaml:"type"`
	AccessTTL  int      `yaml:"accessTTL"`
	RefreshTTL int      `yaml:"refreshTTL"`
	Introspect bool     `yaml:"introspect"`
	Revoke     bool     `yaml:"revoke"`
	Redirects  []string `yaml:"redirects"`
}

type Config struct {
	Server          Server   `yaml:"server"`
	Clients         []Client `yaml:"clients"`
	Users           []User   `yaml:"users"`
	generatedSecret string
	userMap         map[string]*User
	clientMap       map[string]*Client
}

func LoadConfig(name string) Config {
	data, readError := os.ReadFile(name)
	if readError != nil {
		log.Error("Could not read config file: %v", readError)
		os.Exit(1)
	}

	config := Config{}

	parseError := yaml.Unmarshal(data, &config)
	if parseError != nil {
		log.Error("Could not parse config file: %v", parseError)
		os.Exit(1)
	}

	config.userMap = setup[User](&config.Users, func(user User) string {
		return user.Username
	})

	config.clientMap = setup[Client](&config.Clients, func(client Client) string {
		return client.Id
	})

	rand.NewSource(time.Now().UnixNano())
	generatedSecret := fmt.Sprintf("default_%d", rand.Int())
	config.generatedSecret = generatedSecret

	return config
}

func setup[T any](values *[]T, accessor func(T) string) map[string]*T {
	valueMap := make(map[string]*T)

	for index := 0; index < len(*values); index += 1 {
		value := (*values)[index]
		key := accessor(value)
		if key != "" {
			valueMap[key] = &value
		}

	}

	return valueMap
}

func GetOrDefaultString(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	} else {
		return value
	}
}

func GetOrDefaultInt(value int, defaultValue int) int {
	if value == 0 {
		return defaultValue
	} else {
		return value
	}
}

func (config *Config) GetUser(name string) (*User, bool) {
	value, exists := config.userMap[name]
	return value, exists
}

func (config *Config) GetClient(name string) (*Client, bool) {
	value, exists := config.clientMap[name]
	return value, exists
}

func (config *Config) GetAuthCookieName() string {
	return GetOrDefaultString(config.Server.AuthCookieName, "stopnik_auth")
}

func (config *Config) GetIntrospectScope() string {
	return GetOrDefaultString(config.Server.IntrospectScope, "stopnik:introspect")
}

func (config *Config) GetRevokeScope() string {
	return GetOrDefaultString(config.Server.IntrospectScope, "stopnik:revoke")
}

func (config *Config) GetServerSecret() string {
	return GetOrDefaultString(config.Server.Secret, config.generatedSecret)
}

func (client *Client) GetAccessTTL() int {
	return GetOrDefaultInt(client.AccessTTL, 5)
}

func (client *Client) GetRefreshTTL() int {
	return GetOrDefaultInt(client.RefreshTTL, 0)
}
