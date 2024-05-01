package config

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"tiny-gate/src/oauth2"
)

type Client struct {
	Id         string            `yaml:"id"`
	Secret     string            `yaml:"secret"`
	ClientType oauth2.ClientType `yaml:"type"`
}
type Config struct {
	Port    int      `yaml:"port"`
	Clients []Client `yaml:"clients"`
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
