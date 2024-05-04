package main

import (
	"log"
	"os"
	"stopnik/internal/config"
	"stopnik/internal/server"
)

var Version = "development"
var GitHash = "none"

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

	logger.Printf("STOPnik %s - %s", Version, GitHash)

	currentConfig := config.LoadConfig("config.yml")
	logger.Printf("%d", currentConfig.Server.Port)

	server.StartServer(&currentConfig)
}
