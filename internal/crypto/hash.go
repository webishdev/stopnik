package crypto

import (
	"crypto/sha1"
	"crypto/sha512"
	"fmt"
)

func Sha512Hash(value string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(value)))
}

func Sha1Hash(value string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(value)))
}
