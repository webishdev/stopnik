// Package config implements general handling for configuration files
// and adds definition for the configuration file TOML structure.
//
// The static configuration (server and user interface) is loaded once by a Loader.
// The dynamic configuration (clients, users and classifications) is loaded by a DynamicStore
// from directories with one entry per file and can be watched for changes by a Watcher.
package config
