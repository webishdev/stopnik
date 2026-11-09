package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const watcherTestInterval = 10 * time.Millisecond

func startTestWatcher(t *testing.T) (string, *Config) {
	t.Helper()
	baseDir, config, dynamicStore := setupDynamicTest(t, nil)
	dynamicStore.Load()

	watcher := NewWatcher(dynamicStore, watcherTestInterval)
	t.Cleanup(watcher.Close)

	return baseDir, config
}

func expectEventually(t *testing.T, message string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(watcherTestInterval)
	}
	t.Fatal(message)
}

func userExists(config *Config, username string) func() bool {
	return func() bool {
		_, exists := config.GetUser(username)
		return exists
	}
}

func Test_WatcherAddChangeRemove(t *testing.T) {
	baseDir, config := startTestWatcher(t)
	userFile := filepath.Join(baseDir, "user.d", "bar.toml")

	writeTestFile(t, userFile, testUserFile("bar"))
	expectEventually(t, "expected added user bar", userExists(config, "bar"))

	writeTestFile(t, userFile, testUserFile("moo"))
	expectEventually(t, "expected changed user moo", userExists(config, "moo"))

	if removeError := os.Remove(userFile); removeError != nil {
		t.Fatal(removeError)
	}
	expectEventually(t, "expected removed user moo", func() bool {
		return !userExists(config, "moo")()
	})
}

func Test_WatcherInvalidChange(t *testing.T) {
	baseDir, config := startTestWatcher(t)
	userFile := filepath.Join(baseDir, "user.d", "bar.toml")

	writeTestFile(t, userFile, testUserFile("bar"))
	expectEventually(t, "expected added user bar", userExists(config, "bar"))
	version := config.GetDynamicVersion()

	writeTestFile(t, userFile, "[broken\n")
	time.Sleep(20 * watcherTestInterval)
	if config.GetDynamicVersion() != version {
		t.Error("did not expect a change for an invalid file")
	}
	if !userExists(config, "bar")() {
		t.Error("expected user bar to be kept")
	}
}

func Test_WatcherSameContent(t *testing.T) {
	baseDir, config := startTestWatcher(t)
	userFile := filepath.Join(baseDir, "user.d", "bar.toml")

	writeTestFile(t, userFile, testUserFile("bar"))
	expectEventually(t, "expected added user bar", userExists(config, "bar"))
	version := config.GetDynamicVersion()

	future := time.Now().Add(time.Hour)
	if timeError := os.Chtimes(userFile, future, future); timeError != nil {
		t.Fatal(timeError)
	}
	time.Sleep(20 * watcherTestInterval)

	if config.GetDynamicVersion() != version {
		t.Error("did not expect a change for same content")
	}
}

func Test_WatcherRenameReplace(t *testing.T) {
	baseDir, config := startTestWatcher(t)
	userFile := filepath.Join(baseDir, "user.d", "bar.toml")
	writeTestFile(t, userFile, testUserFile("bar"))
	expectEventually(t, "expected added user bar", userExists(config, "bar"))

	tempName := filepath.Join(baseDir, "user.d", "bar.tmp")
	writeTestFile(t, tempName, testUserFile("moo"))
	if renameError := os.Rename(tempName, userFile); renameError != nil {
		t.Fatal(renameError)
	}

	expectEventually(t, "expected replaced user moo", userExists(config, "moo"))
}
