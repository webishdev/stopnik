package config

import "path/filepath"

// ReadFile function definition to read a file by name into []byte.
type ReadFile func(filename string) ([]byte, error)

// Unmarshal function definition to unmarshal a []byte into a general interface.
type Unmarshal func(in []byte, out interface{}) (err error)

// Loader defines how the static configuration is loaded.
type Loader interface {
	// LoadConfig loads the given static configuration, validates if necessary and makes it the current one.
	LoadConfig(name string, validate bool) error
}

type loader struct {
	fileReader  ReadFile
	unmarshaler Unmarshal
}

// NewConfigLoader combines the ReadFile and Unmarshal functions into a Loader.
func NewConfigLoader(fileReader ReadFile, unmarshaler Unmarshal) Loader {
	return &loader{
		fileReader:  fileReader,
		unmarshaler: unmarshaler,
	}
}

func (loader *loader) LoadConfig(name string, validate bool) error {
	data, readError := loader.fileReader(name)
	if readError != nil {
		return readError
	}

	config := &Config{}
	parseError := loader.unmarshaler(data, config)
	if parseError != nil {
		return parseError
	}

	if validate {
		invalidConfigError := config.Validate()
		if invalidConfigError != nil {
			return invalidConfigError
		}
	}

	config.baseDir = filepath.Dir(name)

	return Initialize(config)
}
