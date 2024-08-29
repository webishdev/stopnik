package config

type ReadFile func(filename string) ([]byte, error)
type Unmarshal func(in []byte, out interface{}) (err error)

type Loader struct {
	fileReader  ReadFile
	unmarshaler Unmarshal
}

func NewConfigLoader(fileReader ReadFile, unmarshaler Unmarshal) *Loader {
	return &Loader{
		fileReader:  fileReader,
		unmarshaler: unmarshaler,
	}
}

func (loader *Loader) LoadConfig(name string) (*Config, error) {
	data, readError := loader.fileReader(name)
	if readError != nil {
		return nil, readError
	}

	config := &Config{}
	parseError := loader.unmarshaler(data, config)
	if parseError != nil {
		return nil, parseError
	}

	setupError := config.Setup()
	if setupError != nil {
		return nil, setupError
	}

	return config, nil
}
