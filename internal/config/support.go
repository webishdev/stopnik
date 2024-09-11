package config

import (
	"crypto/rand"
	"fmt"
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

func setup[T any](values *[]T, errorPrefix string, accessor func(T) string) (map[string]*T, error) {
	valueMap := make(map[string]*T)

	for index := 0; index < len(*values); index += 1 {
		value := (*values)[index]
		key := accessor(value)
		if key != "" {
			currentValue := valueMap[key]
			if currentValue != nil {
				return nil, fmt.Errorf("%s '%s' is defined more then once", errorPrefix, key)
			}
			valueMap[key] = &value
		}

	}

	return valueMap, nil
}

// GetOrDefaultStringSlice returns an array or a default array if the given array is empty.
func GetOrDefaultStringSlice(value []string, defaultValue []string) []string {
	if len(value) == 0 {
		return defaultValue
	} else {
		return value
	}
}
