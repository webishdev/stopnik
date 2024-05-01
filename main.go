package main

import (
	"log"
	"os"
	"tiny-gate/src/config"
	"tiny-gate/src/server"
)

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

	cf := config.LoadConfig("config.yml")
	logger.Printf("%d", cf.Server.Port)

	server.StartServer()
}
