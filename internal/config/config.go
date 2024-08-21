package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/webishdev/stopnik/log"
	"math/big"
)

type Keys struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type TLS struct {
	Addr string `yaml:"addr"`
	Keys Keys   `yaml:"keys"`
}

type Server struct {
	LogLevel              string `yaml:"logLevel"`
	Addr                  string `yaml:"addr"`
	AuthCookieName        string `yaml:"authCookieName"`
	Secret                string `yaml:"secret"`
	PrivateKey            string `yaml:"privateKey"`
	TLS                   TLS    `yaml:"tls"`
	LogoutRedirect        string `yaml:"logoutRedirect"`
	IntrospectScope       string `yaml:"introspectScope"`
	RevokeScope           string `yaml:"revokeScopeScope"`
	SessionTimeoutSeconds int    `yaml:"sessionTimeoutSeconds"`
}

type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Claim struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type Client struct {
	Id                      string   `yaml:"id"`
	Secret                  string   `yaml:"secret"`
	ClientType              string   `yaml:"type"`
	AccessTTL               int      `yaml:"accessTTL"`
	RefreshTTL              int      `yaml:"refreshTTL"`
	Introspect              bool     `yaml:"introspect"`
	Revoke                  bool     `yaml:"revoke"`
	Redirects               []string `yaml:"redirects"`
	OpaqueToken             bool     `yaml:"opaqueToken"`
	PasswordFallbackAllowed bool     `yaml:"passwordFallbackAllowed"`
	Claims                  []Claim  `yaml:"claims"`
	Issuer                  string   `yaml:"issuer"`
	Audience                []string `yaml:"audience"`
	PrivateKey              string   `yaml:"privateKey"`
}

type UI struct {
	HideFooter bool   `yaml:"hideFooter"`
	HideMascot bool   `yaml:"hideMascot"`
	Title      string `yaml:"title"`
	FooterText string `yaml:"footerText"`
}

type Config struct {
	Server          Server   `yaml:"server"`
	Clients         []Client `yaml:"clients"`
	Users           []User   `yaml:"users"`
	UI              UI       `yaml:"ui"`
	generatedSecret string
	userMap         map[string]*User
	clientMap       map[string]*Client
}

type ReadFile func(filename string) ([]byte, error)
type Unmarshal func(in []byte, out interface{}) (err error)

type Loader struct {
	fileReader  ReadFile
	unmarshaler Unmarshal
}

func NewConfigLoader(fileReader ReadFile, unmarshaler Unmarshal) *Loader {
	return &Loader{
		fileReader:  fileReader,
		unmarshaler: unmarshaler,
	}
}

func (loader *Loader) LoadConfig(name string) (*Config, error) {
	data, readError := loader.fileReader(name)
	if readError != nil {
		return nil, readError
	}

	config := &Config{}
	parseError := loader.unmarshaler(data, config)
	if parseError != nil {
		return nil, parseError
	}

	setupError := config.Setup()
	if setupError != nil {
		return nil, setupError
	}

	return config, nil
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
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

func GetOrDefaultStringSlice(value []string, defaultValue []string) []string {
	if len(value) == 0 {
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

func (config *Config) Setup() error {
	for userIndex, user := range config.Users {
		if user.Username == "" || len(user.Password) != 128 {
			invalidUser := fmt.Sprintf("User configuration invalid. User %d %v", userIndex, user)
			return errors.New(invalidUser)
		}
	}

	for clientIndex, client := range config.Clients {
		if client.Id == "" || len(client.Secret) != 128 {
			invalidClient := fmt.Sprintf("Client configuration invalid. Client %d %v", clientIndex, client)
			return errors.New(invalidClient)
		}

		if len(client.Redirects) == 0 {
			invalidClient := fmt.Sprintf("Client is missing redirects. Client %d %v", clientIndex, client)
			return errors.New(invalidClient)
		}
	}

	config.userMap = setup[User](&config.Users, func(user User) string {
		return user.Username
	})

	config.clientMap = setup[Client](&config.Clients, func(client Client) string {
		return client.Id
	})

	randomString, randomError := generateRandomString(16)
	if randomError != nil {
		log.Error("Could not generate random secret: %v", randomError)
		return randomError
	}
	generatedSecret := randomString
	config.generatedSecret = generatedSecret

	return nil
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

func (config *Config) GetSessionTimeoutSeconds() int {
	return GetOrDefaultInt(config.Server.SessionTimeoutSeconds, 3600)
}

func (config *Config) GetIntrospectScope() string {
	return GetOrDefaultString(config.Server.IntrospectScope, "stopnik:introspect")
}

func (config *Config) GetRevokeScope() string {
	return GetOrDefaultString(config.Server.RevokeScope, "stopnik:revoke")
}

func (config *Config) GetServerSecret() string {
	return GetOrDefaultString(config.Server.Secret, config.generatedSecret)
}

func (config *Config) GetHideFooter() bool {
	return config.UI.HideFooter
}

func (config *Config) GetHideMascot() bool {
	return config.UI.HideMascot
}

func (config *Config) GetTitle() string {
	return config.UI.Title
}

func (config *Config) GetFooterText() string {
	return GetOrDefaultString(config.UI.FooterText, "STOPnik")
}

func (client *Client) GetAccessTTL() int {
	return GetOrDefaultInt(client.AccessTTL, 5)
}

func (client *Client) GetRefreshTTL() int {
	return GetOrDefaultInt(client.RefreshTTL, 0)
}

func (client *Client) GetIssuer() string {
	return GetOrDefaultString(client.Issuer, "STOPnik")
}

func (client *Client) GetAudience() []string {
	return GetOrDefaultStringSlice(client.Audience, []string{"all"})
}
