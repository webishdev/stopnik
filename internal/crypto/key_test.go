package crypto

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"testing"
)

func Test_Key(t *testing.T) {

	testConfig := &config.Config{
		Server: config.Server{
			Secret: "12345",
		},
	}
	setupError := testConfig.Setup()
	if setupError != nil {
		t.Fatal(setupError)
	}

	testServerKeyLoader(t)

	testLoadPrivateKey(t)

	testLoadNotExistingPrivateKey(t)

	testLoadInvalidPrivateKey(t)

	testLoadUnsupportedCurvePrivateKey(t)
}

func testServerKeyLoader(t *testing.T) {
	t.Run("Server key loader", func(t *testing.T) {
		serverSecretLoader := NewServerSecretLoader()

		key := serverSecretLoader.GetServerKey()

		token, tokenError := jwt.NewBuilder().Subject("foo").Issuer("bar").Build()
		if tokenError != nil {
			t.Fatal(tokenError)
		}
		signedToken, signingError := jwt.Sign(token, key)
		if signingError != nil {
			t.Fatal(signingError)
		}
		if len(signedToken) == 0 {
			t.Errorf("signedToken is empty")
		}

		parsedToken, parseError := jwt.Parse(signedToken, key)
		if parseError != nil {
			t.Fatal(parseError)
		}

		if parsedToken.Subject() != "foo" {
			t.Errorf("parsed token subject does not match, expected foo but got %s", parsedToken.Subject())
		}

		if parsedToken.Issuer() != "bar" {
			t.Errorf("parsed token issuer does not match, expected bar but got %s", parsedToken.Issuer())
		}
	})
}

func testLoadPrivateKey(t *testing.T) {
	type parameter struct {
		fileName string
	}

	var parameters = []parameter{
		{"rsa256key.pem"},
		{"ecdsa256key.pem"},
		{"ecdsa384key.pem"},
		{"ecdsa521key.pem"},
	}

	for _, test := range parameters {
		testMessage := fmt.Sprintf("Load private key from file %v", test.fileName)
		t.Run(testMessage, func(t *testing.T) {

			serverSecretLoader, err := LoadPrivateKey("../../test_keys/" + test.fileName)

			if err != nil {
				t.Fatal(err)
			}

			if serverSecretLoader == nil {
				t.Errorf("Could not load private key")
			}
		})
	}
}

func testLoadNotExistingPrivateKey(t *testing.T) {
	t.Run("Load private key from file which does not exist", func(t *testing.T) {
		_, err := LoadPrivateKey("foo-bar.pem")

		if err == nil {
			t.Errorf("Loaded private key from file which does not exist")
		}
	})
}

func testLoadInvalidPrivateKey(t *testing.T) {
	t.Run("Load private key from invalid file", func(t *testing.T) {
		_, err := LoadPrivateKey("../../test_keys/invalidkey.pem")

		if err == nil {
			t.Errorf("Loaded private key from invalid file")
		}
	})
}

func testLoadUnsupportedCurvePrivateKey(t *testing.T) {
	t.Run("Load private key with unsupported curve", func(t *testing.T) {
		_, err := LoadPrivateKey("../../test_keys/unsupportedcurvekey.pem")

		if err == nil {
			t.Errorf("Loaded private key from with unsupported curve")
		}
	})
}
