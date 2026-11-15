package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/webishdev/stopnik/internal/admin"
	"github.com/webishdev/stopnik/internal/config"
	"github.com/webishdev/stopnik/internal/manager/key"
	"github.com/webishdev/stopnik/internal/system"
	logger "github.com/webishdev/stopnik/log"
)

var Version = "development"
var GitHash = "none"

func main() {
	isHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	addr := flag.String("addr", "localhost:9999", "Address the admin web user interface listens to, e.g. 0.0.0.0:9999")
	basePath := flag.String("base-path", "", "Path prefix the admin web user interface is served under, e.g. /admin")
	configurationDir := flag.String("config-dir", ".config/default", "Configuration directory containing config.toml, client.d, user.d and classification.d")
	secureCookie := flag.Bool("secure-cookie", false, "Always mark the session cookie as secure, use it behind a TLS-terminating proxy")
	flag.Parse()

	if *isHelp {
		fmt.Printf("STOPnik Admin %s - %s\n\n", Version, GitHash)
		flag.Usage()
		os.Exit(0)
	} else if *showVersion {
		fmt.Printf("STOPnik Admin %s - %s\n", Version, GitHash)
		os.Exit(0)
	}

	if startError := start(*addr, *basePath, *configurationDir, *secureCookie); startError != nil {
		fmt.Printf("STOPnik Admin %s - %s\n\n", Version, GitHash)
		fmt.Printf("%v\n", startError)
		os.Exit(1)
	}
}

// start serves the admin web user interface below basePath for the dynamic configuration inside configurationDir.
// Only users with the admin flag can sign in to the web user interface.
func start(addr string, basePath string, configurationDir string, secureCookie bool) error {
	configLoader := config.NewConfigLoader(os.ReadFile, toml.Unmarshal)
	if configError := configLoader.LoadConfig(configurationDir, true); configError != nil {
		return configError
	}
	currentConfig := config.GetConfigInstance()
	logger.SetLogLevel(currentConfig.Server.LogLevel)
	logger.Info("Config loaded from %s", filepath.Join(configurationDir, config.StaticFileName))

	logger.Info("Managing clients in %s, users in %s and classifications in %s", currentConfig.GetClientsDir(), currentConfig.GetUsersDir(), currentConfig.GetClassificationsDir())

	store := admin.NewStore(currentConfig.GetClientsDir(), currentConfig.GetUsersDir(), currentConfig.GetClassificationsDir(), key.ValidateClientKey, currentConfig.GetAllowLegacyHashes())
	handler, handlerError := admin.NewHandler(store, currentConfig, basePath, secureCookie)
	if handlerError != nil {
		return handlerError
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		sig := <-system.GetSignalChannel()
		logger.Debug("Received signal %s", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownError := server.Shutdown(ctx); shutdownError != nil {
			logger.Error("Error shutting down admin server: %v", shutdownError)
		}
	}()

	if !store.HasAdmin() {
		logger.Warn("No user with admin = true exists in %s, add one to sign in to the admin web user interface", currentConfig.GetUsersDir())
	}
	logger.Info("Admin web user interface available at http://%s%s/", addr, strings.TrimSuffix(path.Join("/", basePath), "/"))
	if serveError := server.ListenAndServe(); serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
		return serveError
	}
	return nil
}
