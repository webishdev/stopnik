package key

import (
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/webishdev/stopnik/internal/config"
	"reflect"
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
	t.Run("Ephemeral server key from empty config", func(t *testing.T) {
		resetKeyManager()
		keyManger := GetKeyMangerInstance()
		keys := keyManger.GetAllKeys()

		if len(keys) != 1 || !keys[0].Server {
			t.Fatal("Generated server key should exist")
		}

		if algorithms := keyManger.GetSigningAlgorithms(); !reflect.DeepEqual(algorithms, []jwa.SignatureAlgorithm{jwa.ES256()}) {
			t.Errorf("expected generated key to use ES256, got %v", algorithms)
		}

		// A client without own key uses the server key
		keyLoader := &defaultKeyLoader{keyManager: keyManger}
		managedKey, managedKeyExists := keyLoader.LoadKeys(&config.Client{Id: "no-key"})
		if !managedKeyExists || !managedKey.Server {
			t.Error("Client without own key should use the server key")
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
	}
	testConfigEntries := config.Entries{
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
	if applyError := testConfig.ApplyEntries(testConfigEntries); applyError != nil {
		t.Fatal(applyError)
	}
}

func resetKeyManager() {
	keyManagerLock.Lock()
	defer keyManagerLock.Unlock()
	keyManagerSingleton = nil
}

func Test_ValidateKeys(t *testing.T) {
	type testValidateKeys struct {
		name          string
		serverKey     string
		clientKey     string
		expectedValid bool
	}

	var validateKeysParameter = []testValidateKeys{
		{"no keys", "", "", true},
		{"valid server key", "../../../.test_files/rsa256key.pem", "", true},
		{"valid server and client key", "../../../.test_files/rsa256key.pem", "../../../.test_files/ecdsa521key.pem", true},
		{"invalid server key", "../../../.test_files/invalidkey.pem", "", false},
		{"missing client key", "", "../../../.test_files/missing.pem", false},
	}

	for _, test := range validateKeysParameter {
		t.Run(test.name, func(t *testing.T) {
			testConfig := &config.Config{
				Server: config.Server{
					PrivateKey: test.serverKey,
				},
			}
			testClient := &config.Client{
				Id:         "foo",
				PrivateKey: test.clientKey,
			}

			validateError := ValidateServerKey(testConfig)
			if validateError == nil {
				validateError = ValidateClientKey(testClient)
			}

			if test.expectedValid && validateError != nil {
				t.Errorf("expected keys to be valid, %v", validateError)
			} else if !test.expectedValid && validateError == nil {
				t.Error("expected keys to be invalid")
			}
		})
	}
}

func Test_SigningAlgorithms(t *testing.T) {
	testSetupTestConfig(t)
	resetKeyManager()
	keyManger := GetKeyMangerInstance()

	expectedAlgorithms := []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES512(), jwa.RS256()}
	if algorithms := keyManger.GetSigningAlgorithms(); !reflect.DeepEqual(algorithms, expectedAlgorithms) {
		t.Errorf("signing algorithms %v did not match %v", algorithms, expectedAlgorithms)
	}
}

func Test_ClientKeysFollowDynamicConfiguration(t *testing.T) {
	testSetupTestConfig(t)
	testConfig := config.GetConfigInstance()
	resetKeyManager()
	keyManger := GetKeyMangerInstance()

	if len(keyManger.GetAllKeys()) != 3 {
		t.Fatal("Server and client keys should exist")
	}

	applyError := testConfig.ApplyEntries(config.Entries{
		Clients: []config.Client{
			{
				Id:         "foo",
				Redirects:  []string{"https://example.com/callback"},
				PrivateKey: "../../../.test_files/ecdsa384key.pem",
			},
		},
	})
	if applyError != nil {
		t.Fatal(applyError)
	}

	if len(keyManger.GetAllKeys()) != 2 {
		t.Error("Server key and the key of the remaining client should exist")
	}
}
