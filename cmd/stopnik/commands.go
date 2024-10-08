package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/server"
	"github.com/webishdev/stopnik/internal/system"
	logger "github.com/webishdev/stopnik/log"
	"gopkg.in/yaml.v3"
	"os"
)

// printVersion prints the provided version and git hash value.
func printVersion(version string, gitHash string) {
	fmt.Printf("STOPnik %s - %s\n", version, gitHash)
}

// printHelp prints the flag usage for CLI arguments.
func printHelp(version string, gitHash string) {
	fmt.Printf("STOPnik %s - %s\n\n", version, gitHash)
	flag.Usage()
}

// readPassword reads password and salt from stdin and returns a crypto.Sha512SaltedHash result.
func readPassword() {
	fmt.Printf("Password: ")
	passwordScanner := bufio.NewScanner(os.Stdin)
	passwordScanner.Scan()
	password := passwordScanner.Text()
	fmt.Printf("Salt: ")
	saltScanner := bufio.NewScanner(os.Stdin)
	saltScanner.Scan()
	salt := saltScanner.Text()
	result := crypto.Sha512SaltedHash(password, salt)
	fmt.Printf("Hashed value is: %s\n\n", result)
}

// start starts the STOPnik server configured by the provided configurationFile.
func start(configurationFile *string) error {
	configLoader := config.NewConfigLoader(os.ReadFile, yaml.Unmarshal)

	_, configError := readConfiguration(configurationFile, configLoader)
	if configError != nil {
		return configError
	}

	stopnikServer := server.NewStopnikServer()

	go func() {
		sig := <-system.GetSignalChannel()
		logger.Debug("Received signal %s", sig)
		stopnikServer.Shutdown()
	}()

	stopnikServer.Start()

	return nil
}

// readConfiguration reads and loads the configuration.
func readConfiguration(configurationFile *string, configLoader config.Loader) (*config.Config, error) {
	configError := configLoader.LoadConfig(*configurationFile, true)
	if configError != nil {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		fmt.Printf("%v", configError)
		return nil, configError
	}

	currentConfig := config.GetConfigInstance()
	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", *configurationFile)
	if currentConfig.GetOidc() {
		logger.Info("OpenId Connect is enabled")
	}

	return currentConfig, nil
}
