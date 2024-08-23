package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"os"
)

type SigningPrivateKey struct {
	PrivateKey         interface{}
	SignatureAlgorithm jwa.SignatureAlgorithm
}

func LoadPrivateKey(name string) (*SigningPrivateKey, error) {
	privateKeyBytes, readError := os.ReadFile(name)
	if readError != nil {
		return nil, readError
	}

	privatePem, _ := pem.Decode(privateKeyBytes) // we do not use the 2nd return value "rest"

	parsedPKCS8, pkcs8Error := x509.ParsePKCS8PrivateKey(privatePem.Bytes)
	if pkcs8Error == nil {
		return &SigningPrivateKey{
			PrivateKey:         parsedPKCS8.(*rsa.PrivateKey),
			SignatureAlgorithm: jwa.RS256,
		}, nil
	}

	parsedPKCS1, pkcs1Error := x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if pkcs1Error == nil {
		return &SigningPrivateKey{
			PrivateKey:         parsedPKCS1,
			SignatureAlgorithm: jwa.RS256,
		}, nil
	}

	parsedEC, ecError := x509.ParseECPrivateKey(privatePem.Bytes)
	if ecError == nil {
		curveParams := parsedEC.Curve.Params()
		if curveParams == nil {
			return nil, errors.New("invalid EC curve")
		}
		var signatureAlgorithm jwa.SignatureAlgorithm
		switch curveParams.Name {
		case "P-256":
			signatureAlgorithm = jwa.ES256
		case "P-384":
			signatureAlgorithm = jwa.ES384
		case "P-521":
			signatureAlgorithm = jwa.ES512
		default:
			signatureAlgorithm = ""
		}
		return &SigningPrivateKey{
			PrivateKey:         parsedEC,
			SignatureAlgorithm: signatureAlgorithm,
		}, nil
	}

	return nil, errors.New("invalid private key")
}
