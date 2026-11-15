package main

import (
	"flag"
	"os"
)

var Version = "development"
var GitHash = "none"

func main() {
	isHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	askPassword := flag.Bool("password", false, "Ask for password to create a bcrypt hash")
	configurationDir := flag.String("config-dir", ".config/default", "Configuration directory containing config.toml, client.d, user.d and classification.d")
	flag.Parse()

	if *isHelp {
		printHelp(Version, GitHash)
		os.Exit(0)
	} else if *showVersion {
		printVersion(Version, GitHash)
		os.Exit(0)
	} else if *askPassword {
		readPassword()
		os.Exit(0)
	}

	startError := start(configurationDir)
	if startError != nil {
		os.Exit(1)
	}
}
