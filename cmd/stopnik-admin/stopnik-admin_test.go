package main

import (
	"os"
	"path/filepath"
	"testing"
)

func Test_Start(t *testing.T) {
	type startParameter struct {
		name     string
		config   string
		basePath string
	}

	var startParameters = []startParameter{
		{"Invalid TOML", `[server`, ""},
		{"Invalid config", `[server]
`, ""},
		{"Invalid listen address", `[server]
addr = ":8080"
issuer = "http://localhost:8080"
`, "/admin"},
	}

	for _, test := range startParameters {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if writeError := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(test.config), 0600); writeError != nil {
				t.Fatal(writeError)
			}

			startError := start("localhost:-1", test.basePath, dir, false)

			if startError == nil {
				t.Error("Expected error")
			}
		})
	}

	t.Run("Missing directory", func(t *testing.T) {
		startError := start("localhost:-1", "", filepath.Join(t.TempDir(), "missing"), false)

		if startError == nil {
			t.Error("Expected error")
		}
	})
}
