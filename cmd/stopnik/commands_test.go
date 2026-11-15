package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Test_Version(t *testing.T) {
	output := captureStdout(t, func() {
		printVersion("foo", "bar")
	})

	if output != "STOPnik foo - bar\n" {
		t.Errorf("Expected version output, got '%s'", output)
	}
}

func Test_Help(t *testing.T) {
	output := captureStdout(t, func() {
		printHelp("foo", "bar")
	})

	if !strings.HasPrefix(output, "STOPnik foo - bar\n\n") {
		t.Errorf("Expected help output, got '%s'", output)
	}
}

func Test_ReadPassword(t *testing.T) {
	stdin := writeTempFile(t, "secret\n")
	oldStdin := os.Stdin
	os.Stdin = stdin
	defer func() {
		os.Stdin = oldStdin
	}()

	output := captureStdout(t, readPassword)

	if !strings.Contains(output, "Hashed value is: $2") {
		t.Errorf("Expected bcrypt hash in output, got '%s'", output)
	}
}

func Test_ReadPasswordTooLong(t *testing.T) {
	stdin := writeTempFile(t, strings.Repeat("a", 100)+"\n")
	oldStdin := os.Stdin
	os.Stdin = stdin
	defer func() {
		os.Stdin = oldStdin
	}()

	output := captureStdout(t, readPassword)

	if !strings.Contains(output, "Could not create hash") {
		t.Errorf("Expected hash error in output, got '%s'", output)
	}
}

func Test_LoadStaticConfiguration(t *testing.T) {
	privateKey := testFile(t, "rsa256key.pem")
	cert := testFile(t, "server.crt")
	key := testFile(t, "server.key")

	type loadParameter struct {
		name        string
		config      string
		expectError bool
	}

	var loadParameters = []loadParameter{
		{"Minimal", `[server]
addr = ":8080"
`, false},
		{"With keys and TLS", fmt.Sprintf(`[server]
addr = ":8080"
privateKey = %q

[server.tls]
addr = ":8081"

[server.tls.keys]
cert = %q
key = %q
`, privateKey, cert, key), false},
		{"Invalid TOML", `[server`, true},
		{"Invalid config", `[server]
`, true},
		{"Missing private key", `[server]
addr = ":8080"
privateKey = "does-not-exist.pem"
`, true},
		{"Invalid TLS keys", fmt.Sprintf(`[server]
addr = ":8080"

[server.tls]
addr = ":8081"

[server.tls.keys]
cert = %q
key = %q
`, cert, privateKey), true},
	}

	for _, test := range loadParameters {
		t.Run(test.name, func(t *testing.T) {
			dir := writeConfigDir(t, test.config)

			currentConfig, loadError := loadStaticConfiguration(dir)

			if test.expectError {
				if loadError == nil {
					t.Error("Expected error")
				}
				return
			}
			if loadError != nil {
				t.Fatalf("Unexpected error: %v", loadError)
			}
			if currentConfig == nil || currentConfig.Server.Addr != ":8080" {
				t.Errorf("Expected loaded config, got %v", currentConfig)
			}
		})
	}

	t.Run("Missing directory", func(t *testing.T) {
		_, loadError := loadStaticConfiguration(filepath.Join(t.TempDir(), "missing"))
		if loadError == nil {
			t.Error("Expected error")
		}
	})
}

func Test_StartInvalidConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")

	var startError error
	captureStdout(t, func() {
		startError = start(&dir)
	})

	if startError == nil {
		t.Error("Expected error")
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	tempFile, tempFileError := os.CreateTemp(t.TempDir(), "stdout")
	if tempFileError != nil {
		t.Fatal(tempFileError)
	}
	defer func() {
		_ = tempFile.Close()
	}()

	oldStdout := os.Stdout
	os.Stdout = tempFile
	f()
	os.Stdout = oldStdout

	output, readError := os.ReadFile(tempFile.Name())
	if readError != nil {
		t.Fatal(readError)
	}
	return string(output)
}

func writeTempFile(t *testing.T, content string) *os.File {
	t.Helper()
	tempFile, tempFileError := os.CreateTemp(t.TempDir(), "stdin")
	if tempFileError != nil {
		t.Fatal(tempFileError)
	}
	t.Cleanup(func() {
		_ = tempFile.Close()
	})
	if _, writeError := tempFile.WriteString(content); writeError != nil {
		t.Fatal(writeError)
	}
	if _, seekError := tempFile.Seek(0, 0); seekError != nil {
		t.Fatal(seekError)
	}
	return tempFile
}

func writeConfigDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if writeError := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(content), 0600); writeError != nil {
		t.Fatal(writeError)
	}
	return dir
}

func testFile(t *testing.T, name string) string {
	t.Helper()
	path, pathError := filepath.Abs(filepath.Join("..", "..", ".test_files", name))
	if pathError != nil {
		t.Fatal(pathError)
	}
	return path
}
