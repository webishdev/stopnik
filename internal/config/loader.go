package config

// ReadFile function definition to read a file by name into []byte.
type ReadFile func(filename string) ([]byte, error)

// Unmarshal function definition to unmarshal a []byte into a general interface.
type Unmarshal func(in []byte, out interface{}) (err error)

// Loader defines how a configuration is loaded.
type Loader interface {
	// LoadConfig loads the given configuration and validates if necessary.
	LoadConfig(name string, validate bool) error
	// ReadConfig reads, validates and prepares the given configuration without making it the current one.
	ReadConfig(name string) (*Config, error)
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
	config, parseError := loader.parse(name, validate)
	if parseError != nil {
		return parseError
	}

	initializationError := Initialize(config)
	if initializationError != nil {
		return initializationError
	}

	return nil
}

func (loader *loader) ReadConfig(name string) (*Config, error) {
	config, parseError := loader.parse(name, true)
	if parseError != nil {
		return nil, parseError
	}

	prepareError := prepare(config)
	if prepareError != nil {
		return nil, prepareError
	}

	return config, nil
}

func (loader *loader) parse(name string, validate bool) (*Config, error) {
	data, readError := loader.fileReader(name)
	if readError != nil {
		return nil, readError
	}

	config := &Config{}
	parseError := loader.unmarshaler(data, config)
	if parseError != nil {
		return nil, parseError
	}

	if validate {
		invalidConfigError := config.Validate()
		if invalidConfigError != nil {
			return nil, invalidConfigError
		}
	}

	return config, nil
}
