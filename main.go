package main

import (
	"log"
	"os"
	"stopnik/internal/config"
	"stopnik/internal/server"
)

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

	currentConfig := config.LoadConfig("config.yml")
	logger.Printf("%d", currentConfig.Server.Port)

	server.StartServer(&currentConfig)
}
