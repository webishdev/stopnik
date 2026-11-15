package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/crypto"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/server"
	"github.com/webishdev/stopnik/internal/system"
	logger "github.com/webishdev/stopnik/log"
	"os"
	"path/filepath"
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

// readPassword reads a password from stdin and prints a crypto.BcryptHash result.
func readPassword() {
	fmt.Printf("Password: ")
	passwordScanner := bufio.NewScanner(os.Stdin)
	passwordScanner.Scan()
	password := passwordScanner.Text()
	result, hashError := crypto.BcryptHash(password)
	if hashError != nil {
		fmt.Printf("Could not create hash: %v\n\n", hashError)
		return
	}
	fmt.Printf("Hashed value is: %s\n\n", result)
}

// start starts the STOPnik server configured by the provided configurationDir.
// The static configuration is loaded once, the dynamic configuration (clients, users and classifications)
// is loaded from its directories and watched for changes when enabled.
func start(configurationDir *string) error {
	currentConfig, configError := loadStaticConfiguration(*configurationDir)
	if configError != nil {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		fmt.Printf("%v", configError)
		return configError
	}

	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", filepath.Join(*configurationDir, config.StaticFileName))
	if currentConfig.Server.Issuer == "" {
		logger.Warn("No issuer configured, the issuer will be derived from the Host header of each request, configure server.issuer to avoid manipulated issuer values")
	}

	dynamicStore := config.NewDynamicStore(currentConfig, toml.Unmarshal, key.ValidateClientKey)
	dynamicStore.Load()
	if currentConfig.Dynamic.Watch {
		logger.Info("Watching dynamic configuration every %s", currentConfig.GetDynamicInterval())
		watcher := config.NewWatcher(dynamicStore, currentConfig.GetDynamicInterval())
		defer watcher.Close()
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

// loadStaticConfiguration loads and validates the static configuration from the given configuration directory
// and makes it the current one.
// Beside the configuration itself, the referenced server private key and TLS certificates are validated.
func loadStaticConfiguration(dir string) (*config.Config, error) {
	configLoader := config.NewConfigLoader(os.ReadFile, toml.Unmarshal)
	if configError := configLoader.LoadConfig(dir, true); configError != nil {
		return nil, configError
	}
	currentConfig := config.GetConfigInstance()

	keyError := key.ValidateServerKey(currentConfig)
	if keyError != nil {
		return nil, keyError
	}

	if currentConfig.Server.TLS.Addr != "" {
		_, tlsError := tls.LoadX509KeyPair(currentConfig.Server.TLS.Keys.Cert, currentConfig.Server.TLS.Keys.Key)
		if tlsError != nil {
			return nil, tlsError
		}
	}

	return currentConfig, nil
}
