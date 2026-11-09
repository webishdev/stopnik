package config

import (
	"crypto/rand"
	"math/big"
)

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// GetOrDefaultStringSlice returns an array or a default array if the given array is empty.
func GetOrDefaultStringSlice(value []string, defaultValue []string) []string {
	if len(value) == 0 {
		return defaultValue
	} else {
		return value
	}
}
