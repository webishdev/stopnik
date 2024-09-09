package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/webishdev/stopnik/internal/config"
	"os"
)

// HashAlgorithm used for the names of the supported hash algorithms.
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "SHA256"
	SHA384 HashAlgorithm = "SHA384"
	SHA512 HashAlgorithm = "SHA512"
)

// SigningPrivateKey defines a combination of private key, signing and hash algorithm.
type SigningPrivateKey struct {
	PrivateKey         interface{}
	SignatureAlgorithm jwa.SignatureAlgorithm
	HashAlgorithm      HashAlgorithm
}

// ManagedKey defines a combination of keys defined for config.Client.
type ManagedKey struct {
	Id            string
	Clients       []*config.Client
	Server        bool
	Key           *jwk.Key
	HashAlgorithm HashAlgorithm
}

// ServerSecretLoader defines how to receive a private server key.
type ServerSecretLoader interface {
	// GetServerKey returns the private key of the server.
	GetServerKey() jwt.SignEncryptParseOption
}

type serverSecret struct {
	secret string
}

// KeyLoader defines how to get ManagedKey for a specific client.
type KeyLoader interface {
	// LoadKeys returns a ManagedKey for a specific client and a bool indicating whether a key exists or not.
	LoadKeys(client *config.Client) (*ManagedKey, bool)
	ServerSecretLoader
}

// NewServerSecretLoader creates a ServerSecretLoader based on the current config.Config.
func NewServerSecretLoader() ServerSecretLoader {
	currentConfig := config.GetConfigInstance()
	return &serverSecret{secret: currentConfig.GetServerSecret()}
}

// GetServerKey returns the server secret as jwa.HS256 key.
func (s *serverSecret) GetServerKey() jwt.SignEncryptParseOption {
	return jwt.WithKey(jwa.HS256, []byte(s.secret))
}

// LoadPrivateKey loads a private key from a given filename.
func LoadPrivateKey(filename string) (*SigningPrivateKey, error) {
	privateKeyBytes, readError := os.ReadFile(filename)
	if readError != nil {
		return nil, readError
	}

	privatePem, _ := pem.Decode(privateKeyBytes) // we do not use the 2nd return value "rest"
	if privatePem == nil {
		return nil, errors.New("failed to decode private key")
	}

	parsedPKCS8, pkcs8Error := x509.ParsePKCS8PrivateKey(privatePem.Bytes)
	if pkcs8Error == nil {
		return &SigningPrivateKey{
			PrivateKey:         parsedPKCS8.(*rsa.PrivateKey),
			SignatureAlgorithm: jwa.RS256,
			HashAlgorithm:      SHA256,
		}, nil
	}

	parsedPKCS1, pkcs1Error := x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if pkcs1Error == nil {
		return &SigningPrivateKey{
			PrivateKey:         parsedPKCS1,
			SignatureAlgorithm: jwa.RS256,
			HashAlgorithm:      SHA256,
		}, nil
	}

	parsedEC, ecError := x509.ParseECPrivateKey(privatePem.Bytes)
	if ecError == nil {
		curveParams := parsedEC.Curve.Params()
		if curveParams == nil {
			return nil, errors.New("invalid EC curve")
		}
		var signatureAlgorithm jwa.SignatureAlgorithm
		var hashAlgorithm HashAlgorithm
		switch curveParams.Name {
		case "P-256":
			signatureAlgorithm = jwa.ES256
			hashAlgorithm = SHA256
		case "P-384":
			signatureAlgorithm = jwa.ES384
			hashAlgorithm = SHA384
		case "P-521":
			signatureAlgorithm = jwa.ES512
			hashAlgorithm = SHA512
		default:
			break
		}
		if signatureAlgorithm != "" {
			return &SigningPrivateKey{
				PrivateKey:         parsedEC,
				SignatureAlgorithm: signatureAlgorithm,
				HashAlgorithm:      hashAlgorithm,
			}, nil
		}
	}

	return nil, errors.New("invalid private key")
}
