package config

import (
	"crypto/rand"
	"math/big"
	"slices"
	"stopnik/log"
)

type TLS struct {
	Addr string `yaml:"addr"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Server struct {
	LogLevel        string `yaml:"logLevel"`
	Addr            string `yaml:"addr"`
	AuthCookieName  string `yaml:"authCookieName"`
	Secret          string `yaml:"secret"`
	TokenCert       string `yaml:"tokenCert"`
	TokenKey        string `yaml:"tokenKey"`
	TLS             TLS    `yaml:"tls"`
	LogoutRedirect  string `yaml:"logoutRedirect"`
	IntrospectScope string `yaml:"introspectScope"`
	RevokeScope     string `yaml:"revokeScopeScope"`
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
	Id          string   `yaml:"id"`
	Secret      string   `yaml:"secret"`
	ClientType  string   `yaml:"type"`
	AccessTTL   int      `yaml:"accessTTL"`
	RefreshTTL  int      `yaml:"refreshTTL"`
	Introspect  bool     `yaml:"introspect"`
	Revoke      bool     `yaml:"revoke"`
	Redirects   []string `yaml:"redirects"`
	OpaqueToken bool     `yaml:"opaqueToken"`
	Claims      []Claim  `yaml:"claims"`
	Issuer      string   `yaml:"issuer"`
	Audience    []string `yaml:"audience"`
}

type Config struct {
	Server          Server   `yaml:"server"`
	Clients         []Client `yaml:"clients"`
	Users           []User   `yaml:"users"`
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
	config := &Config{}

	data, readError := loader.fileReader(name)
	if readError != nil {
		log.Error("Could not read config file: %v", readError)
		return config, readError
	}

	parseError := loader.unmarshaler(data, config)
	if parseError != nil {
		log.Error("Could not parse config file: %v", parseError)
		return config, parseError
	}

	config.Users = slices.DeleteFunc(config.Users, func(user User) bool {
		invalid := user.Username == "" || len(user.Password) != 128
		if invalid {
			log.Warn("Invalid username or password, %v", user)
		}
		return invalid
	})

	config.userMap = setup[User](&config.Users, func(user User) string {
		return user.Username
	})

	config.Clients = slices.DeleteFunc(config.Clients, func(client Client) bool {
		invalid := client.Id == "" || len(client.Secret) != 128
		if invalid {
			log.Warn("Invalid id or secret, %v", client)
		}
		return invalid
	})

	config.clientMap = setup[Client](&config.Clients, func(client Client) string {
		return client.Id
	})

	randomString, randomError := generateRandomString(16)
	if randomError != nil {
		log.Error("Could not generate random secret: %v", randomError)
		return config, readError
	}
	generatedSecret := randomString
	config.generatedSecret = generatedSecret

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
	return GetOrDefaultString(config.Server.RevokeScope, "stopnik:revoke")
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

func (client *Client) GetIssuer() string {
	return GetOrDefaultString(client.Issuer, "STOPnik")
}

func (client *Client) GetAudience() []string {
	return GetOrDefaultStringSlice(client.Audience, []string{"all"})
}
