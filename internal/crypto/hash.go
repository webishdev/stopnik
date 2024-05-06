package crypto

import (
	"crypto/sha512"
	"fmt"
)

func Sha512Hash(value string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(value)))
}
