package config

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type configurationHead struct {
	Configuration          *Configuration
	RegisteredUserTypeList []string
}

func ConfigurationHead(path string) (*configurationHead, error) {
	ch := configurationHead{}
	c, err := ch.read(path)
	if err != nil {
		return nil, err
	}

	ch.Configuration = c

	return &ch, nil
}

func (ch *configurationHead) read(path string) (*Configuration, error) {
	result := Configuration{}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	ch.Configuration = &result

	return &result, nil
}
