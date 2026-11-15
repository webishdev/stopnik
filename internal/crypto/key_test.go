package crypto

import (
	"fmt"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"reflect"
	"testing"
)

func Test_Key(t *testing.T) {

	testConfig := &config.Config{
		Server: config.Server{
			Secret: "12345",
		},
	}
	initializationError := config.Initialize(testConfig)
	if initializationError != nil {
		t.Fatal(initializationError)
	}

	testGeneratePrivateKey(t)

	testPurposeServerKeyLoader(t)

	testLoadPrivateKey(t)

	testLoadNotExistingPrivateKey(t)

	testLoadInvalidPrivateKey(t)

	testLoadUnsupportedCurvePrivateKey(t)
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

			serverSecretLoader, err := LoadPrivateKey("../../.test_files/" + test.fileName)

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
		_, err := LoadPrivateKey("../../.test_files/invalidkey.pem")

		if err == nil {
			t.Errorf("Loaded private key from invalid file")
		}
	})
}

func testLoadUnsupportedCurvePrivateKey(t *testing.T) {
	t.Run("Load private key with unsupported curve", func(t *testing.T) {
		_, err := LoadPrivateKey("../../.test_files/unsupportedcurvekey.pem")

		if err == nil {
			t.Errorf("Loaded private key from with unsupported curve")
		}
	})
}

func testPurposeServerKeyLoader(t *testing.T) {
	t.Run("Purpose server key loader", func(t *testing.T) {
		token, tokenError := jwt.NewBuilder().Subject("foo").Build()
		if tokenError != nil {
			t.Fatal(tokenError)
		}
		signedToken, signingError := jwt.Sign(token, NewPurposeServerSecretLoader(PurposeLoginToken).GetServerKey())
		if signingError != nil {
			t.Fatal(signingError)
		}

		_, parseError := jwt.Parse(signedToken, NewPurposeServerSecretLoader(PurposeLoginToken).GetServerKey())
		if parseError != nil {
			t.Errorf("token should be valid for same purpose: %v", parseError)
		}

		_, parseError = jwt.Parse(signedToken, NewPurposeServerSecretLoader(PurposeCookie).GetServerKey())
		if parseError == nil {
			t.Errorf("token should not be valid for other purpose")
		}

		_, parseError = jwt.Parse(signedToken, jwt.WithKey(jwa.HS256(), []byte(config.GetConfigInstance().GetServerSecret())))
		if parseError == nil {
			t.Errorf("token should not be valid with plain server secret")
		}
	})
}

func testGeneratePrivateKey(t *testing.T) {
	t.Run("Generate private key", func(t *testing.T) {
		firstKey, firstError := GeneratePrivateKey()
		secondKey, secondError := GeneratePrivateKey()
		if firstError != nil || secondError != nil {
			t.Fatalf("could not generate private keys: %v %v", firstError, secondError)
		}

		if firstKey.SignatureAlgorithm != jwa.ES256() || firstKey.HashAlgorithm != SHA256 {
			t.Errorf("expected ES256 key, got %s", firstKey.SignatureAlgorithm)
		}

		if reflect.DeepEqual(firstKey.PrivateKey, secondKey.PrivateKey) {
			t.Error("expected generated keys to differ")
		}
	})
}
