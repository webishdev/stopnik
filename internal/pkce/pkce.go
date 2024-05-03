package pkce

import (
	"crypto/sha256"
	"encoding/base64"
)

func ValidatePKCE(method CodeChallengeMethod, value string, verifier string) bool {
	calculatePKCE := calculatePKCE(method, verifier)
	return calculatePKCE == value
}

func calculatePKCE(method CodeChallengeMethod, value string) string {
	valueHash := sha256.Sum256([]byte(value))
	switch method {
	case S256:
		return base64.RawURLEncoding.EncodeToString(valueHash[:])
	default:
		return value
	}

}
