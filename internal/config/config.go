package config

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"tiny-gate/internal/oauth2"
)

type TLS struct {
	Port int    `yaml:"port"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Server struct {
	Port int `yaml:"port"`
	TLS  TLS `yaml:"tls"`
}

type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Client struct {
	Id         string            `yaml:"id"`
	Secret     string            `yaml:"secret"`
	ClientType oauth2.ClientType `yaml:"type"`
}

type Config struct {
	Server    Server   `yaml:"server"`
	Clients   []Client `yaml:"clients"`
	Users     []User   `yaml:"users"`
	userMap   map[string]*User
	clientMap map[string]*Client
}

func LoadConfig(name string) Config {
	data, readError := os.ReadFile(name)
	if readError != nil {
		log.Fatalf("unable to read file: %v", readError)
	}

	config := Config{}

	parseError := yaml.Unmarshal(data, &config)
	if parseError != nil {
		log.Fatalf("error: %v", parseError)
	}

	config.userMap = setup[User](&config.Users, func(user User) string {
		return user.Username
	})

	config.clientMap = setup[Client](&config.Clients, func(client Client) string {
		return client.Id
	})

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

func (config *Config) GetUser(name string) (*User, bool) {
	value, exists := config.userMap[name]
	return value, exists
}

func (config *Config) GetClient(name string) (*Client, bool) {
	value, exists := config.clientMap[name]
	return value, exists
}
