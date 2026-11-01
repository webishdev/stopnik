package crypto

import (
	"crypto/sha1"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"strings"
)

// legacyHashPattern matches the hex encoded SHA512 hashes used before bcrypt was introduced.
var legacyHashPattern = regexp.MustCompile("^[0-9a-f]{128}$")

// unknownBcryptHash and unknownLegacyHash are compared against when the expected hash is not of the related type,
// so every call of VerifySecret costs one bcrypt and one SHA512 calculation,
// independent of whether a user or client exists or which hash type is used.
var unknownBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("stopnik-unknown-secret"), bcrypt.DefaultCost)
var unknownLegacyHash = Sha512Hash("stopnik-unknown-secret")

// Sha512Hash returns a SHA512 hash for the given value.
func Sha512Hash(value string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(value)))
}

// Sha512SaltedHash returns a SHA512 hash for the given value and salt.
func Sha512SaltedHash(value string, salt string) string {
	if salt != "" {
		saltedValue := fmt.Sprintf("%s/!%s", value, salt)
		return Sha512Hash(saltedValue)
	} else {
		return Sha512Hash(value)
	}
}

// Sha1Hash returns a SHA1 hash for the given value.
func Sha1Hash(value string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(value)))
}

// BcryptHash returns a bcrypt hash for the given value, the salt is part of the returned hash.
func BcryptHash(value string) (string, error) {
	hash, hashError := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if hashError != nil {
		return "", hashError
	}
	return string(hash), nil
}

// IsBcryptHash returns whether the given hash is a bcrypt hash.
func IsBcryptHash(hash string) bool {
	_, costError := bcrypt.Cost([]byte(hash))
	return strings.HasPrefix(hash, "$2") && costError == nil
}

// IsLegacyHash returns whether the given hash is a (salted) SHA512 hash.
func IsLegacyHash(hash string) bool {
	return legacyHashPattern.MatchString(hash)
}

// IsSupportedHash returns whether the given hash is either a bcrypt or a (salted) SHA512 hash.
func IsSupportedHash(hash string) bool {
	return IsBcryptHash(hash) || IsLegacyHash(hash)
}

// VerifySecret checks whether the given secret matches the expected bcrypt or (salted) SHA512 hash.
// The salt is only used for SHA512 hashes, as bcrypt hashes contain their own salt.
// The check takes the same time for every hash type and also for an empty expected hash,
// which should be used when a user or client does not exist.
func VerifySecret(secret string, salt string, expectedHash string) bool {
	isBcryptHash := IsBcryptHash(expectedHash)
	isLegacyHash := !isBcryptHash && IsLegacyHash(expectedHash)

	bcryptHash := unknownBcryptHash
	if isBcryptHash {
		bcryptHash = []byte(expectedHash)
	}
	legacyHash := unknownLegacyHash
	if isLegacyHash {
		legacyHash = expectedHash
	}

	validBcrypt := bcrypt.CompareHashAndPassword(bcryptHash, []byte(secret)) == nil
	validLegacy := subtle.ConstantTimeCompare([]byte(Sha512SaltedHash(secret, salt)), []byte(legacyHash)) == 1

	return (isBcryptHash && validBcrypt) || (isLegacyHash && validLegacy)
}
