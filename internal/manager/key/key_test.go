package key

import (
	"github.com/webishdev/stopnik/internal/config"
	"testing"
)

func Test_Keys(t *testing.T) {

	testEmptyConfigKeyManager(t)

	testServerKeyConfigKeyManager(t)

	testServerAndClientKeyConfigKeyManager(t)

	testLoadClientKeys(t)
}

func testEmptyConfigKeyManager(t *testing.T) {
	testConfig := &config.Config{}
	err := config.Initialize(testConfig)
	if err != nil {
		t.Error(err)
	}
	t.Run("No keys from empty config", func(t *testing.T) {
		resetKeyManager()
		keyManger := GetKeyMangerInstance()
		keys := keyManger.GetAllKeys()

		if len(keys) != 0 {
			t.Error("No key should exists")
		}
	})
}

func testServerKeyConfigKeyManager(t *testing.T) {
	testConfig := &config.Config{
		Server: config.Server{
			PrivateKey: "../../../.test_files/rsa256key.pem",
		},
	}
	err := config.Initialize(testConfig)
	if err != nil {
		t.Error(err)
	}

	t.Run("Server key exists", func(t *testing.T) {
		resetKeyManager()
		keyManger := GetKeyMangerInstance()

		keys := keyManger.GetAllKeys()

		if len(keys) != 1 {
			t.Error("One key should exists")
		}
	})
}

func testServerAndClientKeyConfigKeyManager(t *testing.T) {
	testSetupTestConfig(t)
	t.Run("Server and client keys exists", func(t *testing.T) {
		resetKeyManager()
		keyManger := GetKeyMangerInstance()

		keys := keyManger.GetAllKeys()

		if len(keys) != 3 {
			t.Error("Multiple keys should exists")
		}
	})
}

func testLoadClientKeys(t *testing.T) {
	testSetupTestConfig(t)
	testConfig := config.GetConfigInstance()
	t.Run("Load specific client key", func(t *testing.T) {
		resetKeyManager()
		keyLoader := GetDefaultKeyLoaderInstance()

		client, clientExists := testConfig.GetClient("foo")
		if !clientExists {
			t.Error("Client should exist")
		}

		managedKey, mangedKeyExists := keyLoader.LoadKeys(client)
		if !mangedKeyExists {
			t.Error("Managed key should exist")
		}

		if managedKey.Server {
			t.Error("Managed key should not match server key")
		}
	})
}

func testSetupTestConfig(t *testing.T) {
	testConfig := &config.Config{
		Server: config.Server{
			PrivateKey: "../../../.test_files/rsa256key.pem",
		},
		Clients: []config.Client{
			{
				Id:           "foo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				PrivateKey:   "../../../.test_files/ecdsa256key.pem",
			},
			{
				Id:           "bar",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				PrivateKey:   "../../../.test_files/rsa256key.pem",
			},
			{
				Id:           "moo",
				ClientSecret: "d82c4eb5261cb9c8aa9855edd67d1bd10482f41529858d925094d173fa662aa91ff39bc5b188615273484021dfb16fd8284cf684ccf0fc795be3aa2fc1e6c181",
				Redirects:    []string{"https://example.com/callback"},
				PrivateKey:   "../../../.test_files/ecdsa521key.pem",
			},
		},
	}

	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}
}

func resetKeyManager() {
	keyManagerLock.Lock()
	defer keyManagerLock.Unlock()
	keyManagerSingleton = nil
}
