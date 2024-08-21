package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadPrivateKey(name string) (interface{}, error) {
	privateKeyBytes, readError := os.ReadFile(name)
	if readError != nil {
		return nil, readError
	}

	privatePem, _ := pem.Decode(privateKeyBytes) // we do not use the 2nd return value "rest"

	parsedPKCS8, pkcs8Error := x509.ParsePKCS8PrivateKey(privatePem.Bytes)
	if pkcs8Error == nil {
		return parsedPKCS8.(*rsa.PrivateKey), nil
	}

	parsedPKCS1, pkcs1Error := x509.ParsePKCS1PrivateKey(privatePem.Bytes)
	if pkcs1Error == nil {
		return parsedPKCS1, nil
	}

	parsedEC, ecError := x509.ParseECPrivateKey(privatePem.Bytes)
	if ecError == nil {
		return parsedEC, nil
	}

	return nil, errors.New("invalid private key")
}
