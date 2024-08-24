package crypto

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
)

func Sha512Hash(value string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(value)))
}

func Sha512SaltedHash(value string, salt string) string {
	if salt != "" {
		saltedValue := fmt.Sprintf("%s/!%s", value, salt)
		return Sha512Hash(saltedValue)
	} else {
		return Sha512Hash(value)
	}
}

func Sha1Hash(value string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(value)))
}
