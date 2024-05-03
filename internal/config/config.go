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
	Server  Server   `yaml:"server"`
	Clients []Client `yaml:"clients"`
	Users   []User   `yaml:"users"`
	userMap map[string]*User
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

	config.userMap = make(map[string]*User)
	for userIndex := 0; userIndex < len(config.Users); userIndex += 1 {
		if config.Users[userIndex].Username != "" {
			config.userMap[config.Users[userIndex].Username] = &config.Users[userIndex]
		}

	}

	return config
}

func (config *Config) GetUser(name string) (*User, bool) {
	value, exists := config.userMap[name]
	return value, exists
}
