package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

const watcherTestInterval = 10 * time.Millisecond

func watcherTestConfig(addr string) string {
	return `[server]
addr = "` + addr + `"

[[clients]]
id = "foo"
redirects = ["https://example.com/callback"]

[[users]]
username = "foo"
password = "$2a$10$jvXVHUYe.kb5njbxI2QUOOY/TDDi880X0jC01h1CrhUNagGN.KcDq"
`
}

func startTestWatcher(t *testing.T, content string) (string, chan *Config) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "config.toml")
	writeTestFile(t, name, content)

	configLoader := NewConfigLoader(os.ReadFile, toml.Unmarshal)
	reloads := make(chan *Config, 10)
	watcher := NewWatcher(name, watcherTestInterval, configLoader.ReadConfig, func(config *Config) {
		reloads <- config
	})
	t.Cleanup(watcher.Close)

	return name, reloads
}

func writeTestFile(t *testing.T, name string, content string) {
	t.Helper()
	if writeError := os.WriteFile(name, []byte(content), 0600); writeError != nil {
		t.Fatal(writeError)
	}
	// make sure the modification time changes, even on file systems with coarse timestamps
	future := time.Now().Add(time.Duration(len(content)) * time.Second)
	if timeError := os.Chtimes(name, future, future); timeError != nil {
		t.Fatal(timeError)
	}
}

func expectReload(t *testing.T, reloads chan *Config) *Config {
	t.Helper()
	select {
	case config := <-reloads:
		return config
	case <-time.After(2 * time.Second):
		t.Fatal("expected configuration reload")
		return nil
	}
}

func expectNoReload(t *testing.T, reloads chan *Config) {
	t.Helper()
	select {
	case config := <-reloads:
		t.Fatalf("did not expect configuration reload, got %v", config.Server.Addr)
	case <-time.After(20 * watcherTestInterval):
	}
}

func Test_WatcherValidChange(t *testing.T) {
	name, reloads := startTestWatcher(t, watcherTestConfig(":8080"))

	writeTestFile(t, name, watcherTestConfig(":9090"))

	config := expectReload(t, reloads)
	if config.Server.Addr != ":9090" {
		t.Errorf("expected changed address, got %s", config.Server.Addr)
	}
}

func Test_WatcherInvalidChange(t *testing.T) {
	type testInvalidContent struct {
		name    string
		content string
	}

	var invalidContentParameter = []testInvalidContent{
		{"broken TOML", "[server\naddr = "},
		{"invalid config", "[server]\naddr = \":8080\"\n"},
	}

	for _, test := range invalidContentParameter {
		t.Run(test.name, func(t *testing.T) {
			name, reloads := startTestWatcher(t, watcherTestConfig(":8080"))

			writeTestFile(t, name, test.content)
			expectNoReload(t, reloads)

			writeTestFile(t, name, watcherTestConfig(":9090"))
			config := expectReload(t, reloads)
			if config.Server.Addr != ":9090" {
				t.Errorf("expected changed address after fixing file, got %s", config.Server.Addr)
			}
		})
	}
}

func Test_WatcherSameContent(t *testing.T) {
	name, reloads := startTestWatcher(t, watcherTestConfig(":8080"))

	future := time.Now().Add(time.Hour)
	if timeError := os.Chtimes(name, future, future); timeError != nil {
		t.Fatal(timeError)
	}

	expectNoReload(t, reloads)
}

func Test_WatcherRenameReplace(t *testing.T) {
	name, reloads := startTestWatcher(t, watcherTestConfig(":8080"))

	tempName := name + ".tmp"
	writeTestFile(t, tempName, watcherTestConfig(":9090"))
	if renameError := os.Rename(tempName, name); renameError != nil {
		t.Fatal(renameError)
	}

	config := expectReload(t, reloads)
	if config.Server.Addr != ":9090" {
		t.Errorf("expected changed address, got %s", config.Server.Addr)
	}
}

func Test_WatcherMissingFile(t *testing.T) {
	name, reloads := startTestWatcher(t, watcherTestConfig(":8080"))

	if removeError := os.Remove(name); removeError != nil {
		t.Fatal(removeError)
	}
	expectNoReload(t, reloads)

	writeTestFile(t, name, watcherTestConfig(":9090"))
	expectReload(t, reloads)
}
