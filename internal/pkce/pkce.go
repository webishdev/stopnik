package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"github.com/webishdev/stopnik/internal/system"
	"github.com/webishdev/stopnik/log"
)

// ValidatePKCE checks whether the code verifier matches the code challenge of the authorization request.
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
// The values are compared in constant time.
func ValidatePKCE(method CodeChallengeMethod, codeChallenge string, codeVerifier string) bool {
	calculatedCodeChallenge := CalculatePKCE(method, codeVerifier)
	return subtle.ConstantTimeCompare([]byte(calculatedCodeChallenge), []byte(codeChallenge)) == 1
}

// CalculatePKCE calculates the code challenge for the given code verifier.
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
func CalculatePKCE(method CodeChallengeMethod, codeVerifier string) string {
	log.Debug("Calculating PKCE: %s", method)
	switch method {
	case S256:
		valueHash := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(valueHash[:])
	default:
		return codeVerifier
	}
}

// IsValidCodeVerifier returns whether the code verifier has 43 to 128 characters of the unreserved characters.
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
// code-verifier = 43*128unreserved, unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
func IsValidCodeVerifier(codeVerifier string) bool {
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return false
	}
	for _, character := range codeVerifier {
		if !isUnreserved(character) {
			return false
		}
	}
	return true
}

// IsValidS256CodeChallenge returns whether the code challenge is a base64url encoded SHA-256 hash without padding.
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
func IsValidS256CodeChallenge(codeChallenge string) bool {
	if len(codeChallenge) != 43 {
		return false
	}
	for _, character := range codeChallenge {
		if !isBase64URL(character) {
			return false
		}
	}
	return true
}

// GenerateCodeVerifier returns a new random code verifier with 43 characters.
// https://datatracker.ietf.org/doc/html/rfc7636#section-7.1
func GenerateCodeVerifier() string {
	randomBytes := make([]byte, 32)
	_, randomError := rand.Read(randomBytes)
	if randomError != nil {
		system.CriticalError(randomError)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

func isBase64URL(character rune) bool {
	return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || character == '_'
}

func isUnreserved(character rune) bool {
	return isBase64URL(character) || character == '.' || character == '~'
}
