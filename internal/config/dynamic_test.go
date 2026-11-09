package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

const testPassword = "$2a$10$jvXVHUYe.kb5njbxI2QUOOY/TDDi880X0jC01h1CrhUNagGN.KcDq"

func testClientFile(id string) string {
	return "id = \"" + id + "\"\nredirects = [\"https://example.com/callback\"]\n"
}

func testUserFile(username string) string {
	return "username = \"" + username + "\"\npassword = \"" + testPassword + "\"\n"
}

func testClassificationFile(username string) string {
	return "user = \"" + username + "\"\nclient = \"foo\"\n\n[[claims]]\nname = \"role\"\nvalue = \"admin\"\n"
}

// setupDynamicTest creates a static Config with dynamic directories inside a temporary directory.
func setupDynamicTest(t *testing.T, clientCheck ClientCheck) (string, *Config, *DynamicStore) {
	t.Helper()
	baseDir := t.TempDir()
	for _, dir := range []string{"client.d", "user.d", "classification.d"} {
		if mkdirError := os.Mkdir(filepath.Join(baseDir, dir), 0700); mkdirError != nil {
			t.Fatal(mkdirError)
		}
	}

	config := &Config{baseDir: baseDir}
	if initializationError := Initialize(config); initializationError != nil {
		t.Fatal(initializationError)
	}

	return baseDir, config, NewDynamicStore(config, toml.Unmarshal, clientCheck)
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

func Test_DynamicStoreLoad(t *testing.T) {
	baseDir, config, dynamicStore := setupDynamicTest(t, nil)
	writeTestFile(t, filepath.Join(baseDir, "client.d", "foo.toml"), testClientFile("foo"))
	writeTestFile(t, filepath.Join(baseDir, "user.d", "bar.toml"), testUserFile("bar"))
	writeTestFile(t, filepath.Join(baseDir, "classification.d", "bar.toml"), testClassificationFile("bar"))
	writeTestFile(t, filepath.Join(baseDir, "user.d", "ignored.txt"), testUserFile("ignored"))

	dynamicStore.Load()

	if _, exists := config.GetClient("foo"); !exists {
		t.Error("expected client foo")
	}
	if _, exists := config.GetUser("bar"); !exists {
		t.Error("expected user bar")
	}
	if _, exists := config.GetUser("ignored"); exists {
		t.Error("expected files without .toml extension to be ignored")
	}
	if claims := config.GetClaims("bar", "foo", nil); len(claims) != 1 {
		t.Errorf("expected one claim, got %d", len(claims))
	}
}

func Test_DynamicStoreInvalidFileSkipped(t *testing.T) {
	baseDir, config, dynamicStore := setupDynamicTest(t, nil)
	writeTestFile(t, filepath.Join(baseDir, "user.d", "bar.toml"), testUserFile("bar"))
	writeTestFile(t, filepath.Join(baseDir, "user.d", "broken.toml"), "username = \"broken\"\n")
	writeTestFile(t, filepath.Join(baseDir, "client.d", "broken.toml"), "id = \"broken\n")

	dynamicStore.Load()

	if _, exists := config.GetUser("bar"); !exists {
		t.Error("expected valid user bar")
	}
	if _, exists := config.GetUser("broken"); exists {
		t.Error("expected invalid user to be skipped")
	}
	if len(config.GetClients()) != 0 {
		t.Error("expected invalid client to be skipped")
	}
}

func Test_DynamicStoreChanges(t *testing.T) {
	baseDir, config, dynamicStore := setupDynamicTest(t, nil)
	userFile := filepath.Join(baseDir, "user.d", "bar.toml")
	writeTestFile(t, userFile, testUserFile("bar"))
	dynamicStore.Load()

	// an invalid change keeps the previous valid entry
	writeTestFile(t, userFile, "username = \"bar\"\n")
	dynamicStore.Load()
	if _, exists := config.GetUser("bar"); !exists {
		t.Error("expected previous user bar to be kept")
	}

	// a valid change replaces the entry
	writeTestFile(t, userFile, testUserFile("moo"))
	dynamicStore.Load()
	if _, exists := config.GetUser("bar"); exists {
		t.Error("expected user bar to be replaced")
	}
	if _, exists := config.GetUser("moo"); !exists {
		t.Error("expected user moo")
	}

	// a removed file removes the entry
	if removeError := os.Remove(userFile); removeError != nil {
		t.Fatal(removeError)
	}
	dynamicStore.Load()
	if _, exists := config.GetUser("moo"); exists {
		t.Error("expected user moo to be removed")
	}
}

func Test_DynamicStoreDuplicates(t *testing.T) {
	baseDir, config, dynamicStore := setupDynamicTest(t, nil)
	writeTestFile(t, filepath.Join(baseDir, "client.d", "a.toml"), testClientFile("foo")+"oidc = true\n")
	writeTestFile(t, filepath.Join(baseDir, "client.d", "b.toml"), testClientFile("foo"))

	dynamicStore.Load()

	client, exists := config.GetClient("foo")
	if !exists || !client.Oidc {
		t.Error("expected client foo from first file")
	}
	if len(config.GetClients()) != 1 {
		t.Errorf("expected one client, got %d", len(config.GetClients()))
	}
}

func Test_DynamicStoreClientCheck(t *testing.T) {
	baseDir, config, dynamicStore := setupDynamicTest(t, func(client *Client) error {
		if client.PrivateKey != "" {
			return errors.New("key not found")
		}
		return nil
	})
	writeTestFile(t, filepath.Join(baseDir, "client.d", "foo.toml"), testClientFile("foo"))
	writeTestFile(t, filepath.Join(baseDir, "client.d", "bar.toml"), testClientFile("bar")+"privateKey = \"missing.pem\"\n")

	dynamicStore.Load()

	if _, exists := config.GetClient("foo"); !exists {
		t.Error("expected client foo")
	}
	if _, exists := config.GetClient("bar"); exists {
		t.Error("expected client with failing check to be skipped")
	}
}

func Test_DynamicStoreMissingDirectories(t *testing.T) {
	config := &Config{baseDir: filepath.Join(t.TempDir(), "missing")}
	if initializationError := Initialize(config); initializationError != nil {
		t.Fatal(initializationError)
	}

	NewDynamicStore(config, toml.Unmarshal, nil).Load()

	if len(config.GetClients()) != 0 {
		t.Error("expected no clients")
	}
}
