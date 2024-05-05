package main

import (
	"stopnik/internal/config"
	"stopnik/internal/server"
	"stopnik/log"
)

var Version = "development"
var GitHash = "none"

func main() {
	log.Info("STOPnik %s - %s", Version, GitHash)

	configFile := "config.yml"

	currentConfig := config.LoadConfig(configFile)
	log.Info("Config loaded from %s", configFile)

	server.StartServer(&currentConfig)
}
