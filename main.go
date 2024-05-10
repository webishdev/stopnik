package main

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"stopnik/internal/config"
	"stopnik/internal/server"
	logger "stopnik/log"
)

var Version = "development"
var GitHash = "none"

func main() {
	isHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	configurationFile := flag.String("file", "config.yml", "Configuration file to use")
	flag.Parse()

	if *isHelp {
		flag.Usage()
		os.Exit(0)
	} else if *showVersion {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		os.Exit(0)
	}

	configLoader := config.NewConfigLoader(os.ReadFile, yaml.Unmarshal)

	currentConfig := configLoader.LoadConfig(*configurationFile)
	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", *configurationFile)

	server.StartServer(&currentConfig)
}
