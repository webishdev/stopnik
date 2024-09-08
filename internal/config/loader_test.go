package config

import (
	"errors"
	"testing"
)

func Test_ReadError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return nil, errors.New("test error")
	}, nil)

	err := configLoader.LoadConfig("foo.txt", false)

	if err == nil {
		t.Error("expected error")
	}
}

func Test_UnmarshalError(t *testing.T) {
	configLoader := NewConfigLoader(func(filename string) ([]byte, error) {
		return make([]byte, 10), nil
	}, func(in []byte, out interface{}) (err error) {
		return errors.New("test error")
	})

	err := configLoader.LoadConfig("foo.txt", false)

	if err == nil {
		t.Error("expected error")
	}
}
