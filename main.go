package main

import (
	"flag"
	"fmt"
	"github.com/webishdev/stopnik/cmd"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/server"
	logger "github.com/webishdev/stopnik/log"
	"gopkg.in/yaml.v3"
	"os"
	"os/signal"
	"syscall"
)

var Version = "development"
var GitHash = "none"

func main() {
	isHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	askPassword := flag.Bool("password", false, "Ask for password and salt to create hash")
	configurationFile := flag.String("file", "config.yml", "Configuration file to use")
	flag.Parse()

	if *isHelp {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		flag.Usage()
		os.Exit(0)
	} else if *showVersion {
		fmt.Printf("STOPnik %s - %s\n", Version, GitHash)
		os.Exit(0)
	} else if *askPassword {
		cmd.ReadPassword()
		os.Exit(0)
	}

	configLoader := config.NewConfigLoader(os.ReadFile, yaml.Unmarshal)

	currentConfig, configError := configLoader.LoadConfig(*configurationFile)
	if configError != nil {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		fmt.Printf("%v", configError)
		os.Exit(1)
	}
	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", *configurationFile)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	stopnikServer := server.NewStopnikServer(currentConfig)

	go func() {
		sig := <-sigs
		logger.Debug("Received signal %s", sig)
		stopnikServer.Shutdown()
	}()

	stopnikServer.Start()

}
