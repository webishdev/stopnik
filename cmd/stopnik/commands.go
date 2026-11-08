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
	"time"
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

// configurationCheckInterval defines how often the configuration file is checked for changes.
const configurationCheckInterval = 2 * time.Second

// start starts the STOPnik server configured by the provided configurationFile.
// The configuration file is watched, a valid change restarts the server with the new configuration,
// an invalid change is ignored and the previous configuration stays active.
func start(configurationFile *string) error {
	configLoader := config.NewConfigLoader(os.ReadFile, toml.Unmarshal)
	readAndValidate := func(name string) (*config.Config, error) {
		return readConfiguration(name, configLoader)
	}

	initialConfig, configError := readAndValidate(*configurationFile)
	if configError != nil {
		fmt.Printf("STOPnik %s - %s\n\n", Version, GitHash)
		fmt.Printf("%v", configError)
		return configError
	}

	applyConfiguration(*configurationFile, initialConfig)

	reloads := make(chan *config.Config, 1)
	watcher := config.NewWatcher(*configurationFile, configurationCheckInterval, readAndValidate, func(nextConfig *config.Config) {
		// only the latest valid configuration is of interest
		select {
		case <-reloads:
		default:
		}
		reloads <- nextConfig
	})
	defer watcher.Close()

	signals := system.GetSignalChannel()

	for {
		stopnikServer := server.NewStopnikServer()
		done := make(chan struct{})
		go func() {
			stopnikServer.Start()
			close(done)
		}()

		select {
		case sig := <-signals:
			logger.Debug("Received signal %s", sig)
			stopnikServer.Shutdown()
			<-done
			return nil
		case nextConfig := <-reloads:
			stopnikServer.Shutdown()
			<-done
			server.ResetInstances()
			applyConfiguration(*configurationFile, nextConfig)
		}
	}
}

// readConfiguration reads and validates the configuration without applying it.
// Beside the configuration itself, referenced private keys and TLS certificates are validated.
func readConfiguration(name string, configLoader config.Loader) (*config.Config, error) {
	currentConfig, configError := configLoader.ReadConfig(name)
	if configError != nil {
		return nil, configError
	}

	keyError := key.ValidateKeys(currentConfig)
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

// applyConfiguration makes the given, already validated and prepared configuration the current one.
func applyConfiguration(name string, currentConfig *config.Config) {
	config.Activate(currentConfig)

	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", name)
	if currentConfig.GetOidc() {
		logger.Info("OpenId Connect is enabled")
	}
	if currentConfig.Server.Issuer == "" {
		logger.Warn("No issuer configured, the issuer will be derived from the Host header of each request, configure server.issuer to avoid manipulated issuer values")
	}
}
