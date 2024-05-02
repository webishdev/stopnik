package config

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"tiny-gate/internal/oauth2"
)

type Server struct {
	Port int `yaml:"port"`
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

	return config
}
