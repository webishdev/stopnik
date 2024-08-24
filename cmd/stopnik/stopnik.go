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
	askPassword := flag.Bool("password", false, "Ask for password and salt to create hash")
	configurationFile := flag.String("file", "config.yml", "Configuration file to use")
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

	startError := start(configurationFile)
	if startError != nil {
		os.Exit(1)
	}
}
