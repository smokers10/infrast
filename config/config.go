package config

import (
	"errors"
	"io"
	"os"
	"strings"

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

	result.UserManagement.UserCredential = ch.prepareUserCredential(result.UserManagement.UserCredential)

	ch.Configuration = &result

	return &result, nil
}

func (ch *configurationHead) prepareUserCredential(userCredentials []UserCredential) (results []UserCredential) {
	for _, v := range userCredentials {
		UCTemp := UserCredential{
			Type:                 strings.ToLower(v.Type),
			UserTable:            strings.ToLower(v.UserTable),
			IDProperty:           strings.ToLower(v.IDProperty),
			PhotoProfileProperty: strings.ToLower(v.PhotoProfileProperty),
			PasswordProperty:     strings.ToLower(v.PasswordProperty),
			UsernameProperty:     strings.ToLower(v.UsernameProperty),
			EmailProperty:        strings.ToLower(v.EmailProperty),
			PhoneProperty:        strings.ToLower(v.PhoneProperty),
		}

		for _, q := range v.Credential {
			UCTemp.Credential = append(UCTemp.Credential, strings.ToLower(q))
		}

		results = append(results, UCTemp)
	}
	return results
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
