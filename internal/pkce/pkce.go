package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/webishdev/stopnik/log"
)

func ValidatePKCE(method CodeChallengeMethod, verifier string, value string) bool {
	calculatePKCE := CalculatePKCE(method, value)
	return calculatePKCE == verifier
}

func CalculatePKCE(method CodeChallengeMethod, value string) string {
	log.Debug("Calculating PKCE: %s %s", method, value)
	switch method {
	case S256:
		valueHash := sha256.Sum256([]byte(value))
		return base64.RawURLEncoding.EncodeToString(valueHash[:])
	default:
		return value
	}

}
