package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

func Reader(path string) (*Configuration, error) {
	result := Configuration{}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
