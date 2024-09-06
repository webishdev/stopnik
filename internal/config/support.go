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

func setup[T any](values *[]T, accessor func(T) string) map[string]*T {
	valueMap := make(map[string]*T)

	for index := 0; index < len(*values); index += 1 {
		value := (*values)[index]
		key := accessor(value)
		if key != "" {
			valueMap[key] = &value
		}

	}

	return valueMap
}

// GetOrDefaultString returns a value or a default value if the given value is empty.
func GetOrDefaultString(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	} else {
		return value
	}
}

// GetOrDefaultStringSlice returns an array or a default array if the given array is empty.
func GetOrDefaultStringSlice(value []string, defaultValue []string) []string {
	if len(value) == 0 {
		return defaultValue
	} else {
		return value
	}
}

// GetOrDefaultInt returns a value or a default value if the given value is empty.
func GetOrDefaultInt(value int, defaultValue int) int {
	if value == 0 {
		return defaultValue
	} else {
		return value
	}
}
