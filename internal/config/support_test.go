package config

import (
	"reflect"
	"testing"
)

func Test_DefaultValues(t *testing.T) {
	t.Run("Default value as string", func(t *testing.T) {
		assertDefaultValues[string](t, "abc", "def", GetOrDefaultString, func(a string) bool {
			return a == "abc"
		})

		assertDefaultValues[string](t, "", "def", GetOrDefaultString, func(a string) bool {
			return a == "def"
		})
	})

	t.Run("Default value as []string", func(t *testing.T) {
		assertDefaultValues[[]string](t, []string{"abc", "def"}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"abc", "def"})
		})

		assertDefaultValues[[]string](t, []string{}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"ghi", "jkl"})
		})
	})

	t.Run("Default value as int", func(t *testing.T) {
		assertDefaultValues[int](t, 22, 23, GetOrDefaultInt, func(a int) bool {
			return a == 22
		})

		assertDefaultValues[int](t, 0, 23, GetOrDefaultInt, func(a int) bool {
			return a == 23
		})
	})
}
