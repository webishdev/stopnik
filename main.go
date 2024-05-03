package main

import (
	_ "embed"
	"log"
	"os"
	"stopnik/internal/config"
	"stopnik/internal/server"
	"strings"
)

//go:embed resources/version
var version []byte

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

	versionLines := strings.Split(string(version), "\n")
	if len(versionLines) < 2 {
		panic("Something went wrong")
	}

	version := versionLines[0]
	commitHash := versionLines[1]

	logger.Printf("STOPnik %s - %s", version, commitHash)

	currentConfig := config.LoadConfig("config.yml")
	logger.Printf("%d", currentConfig.Server.Port)

	server.StartServer(&currentConfig)
}
