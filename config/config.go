package config

import (
	"errors"
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

type configurationHead struct {
	Configuration          *Configuration
	RegisteredUserTypeList []string
}

func ConfigurationHead() *configurationHead {
	return &configurationHead{}
}

func (ch *configurationHead) Read(path string) (*Configuration, error) {
	result := Configuration{}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	ch.Configuration = &result

	return &result, nil
}

func (ch *configurationHead) RegisteredUserType() ([]string, error) {
	userTypes := []string{}

	if len(ch.Configuration.UserManagement.UserCredential) == 0 {
		return nil, errors.New("no user credential data! make sure your configuration YAML is following the prefered format or call the read method first")
	}

	for _, v := range ch.Configuration.UserManagement.UserCredential {
		userTypes = append(userTypes, v.Type)
	}

	return userTypes, nil
}
