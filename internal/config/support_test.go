package config

import (
	"reflect"
	"testing"
)

func Test_GetOrDefaultStringSlice(t *testing.T) {
	t.Run("Default value as []string", func(t *testing.T) {
		assertDefaultValues[[]string](t, []string{"abc", "def"}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"abc", "def"})
		})

		assertDefaultValues[[]string](t, []string{}, []string{"ghi", "jkl"}, GetOrDefaultStringSlice, func(a []string) bool {
			return reflect.DeepEqual(a, []string{"ghi", "jkl"})
		})
	})
}
