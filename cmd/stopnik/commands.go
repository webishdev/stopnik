package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/server"
	logger "github.com/webishdev/stopnik/log"
	"gopkg.in/yaml.v3"
	"os"
	"os/signal"
	"syscall"
)

func printVersion(version string, gitHash string) {
	fmt.Printf("STOPnik %s - %s\n", version, gitHash)
}

func printHelp(version string, gitHash string) {
	fmt.Printf("STOPnik %s - %s\n\n", version, gitHash)
	flag.Usage()
}

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

func start(configurationFile *string) error {
	configLoader := config.NewConfigLoader(os.ReadFile, yaml.Unmarshal)

	currentConfig, configError := readConfiguration(configurationFile, configLoader)
	if configError != nil {
		return configError
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	stopnikServer := server.NewStopnikServer(currentConfig)

	go func() {
		sig := <-sigs
		logger.Debug("Received signal %s", sig)
		stopnikServer.Shutdown()
	}()

	stopnikServer.Start()

	return nil
}

func readConfiguration(configurationFile *string, configLoader *config.Loader) (*config.Config, error) {
	currentConfig, configError := configLoader.LoadConfig(*configurationFile)
	if configError != nil {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		fmt.Printf("%v", configError)
		return nil, configError
	}
	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", *configurationFile)

	return currentConfig, nil
}
