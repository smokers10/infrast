package firebase

import (
	"errors"
	"io"
	"os"
	"testing"

	"firebase.google.com/go/messaging"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const (
	fcmTokenPath      = "fcm_registration_tokens.yaml"
	configurationPath = "config.yaml"
)

type FCMList struct {
	RegistrationTokens []string `yaml:"tokens"`
}

func TestSend(t *testing.T) {
	f, err := initFCM()
	assert.NoError(t, err)

	tokens, err := getTokens(fcmTokenPath)
	assert.NoError(t, err)

	t.Run("send single message", func(t *testing.T) {
		msg := &messaging.Message{
			Notification: &messaging.Notification{
				Title: "test notification from BE",
				Body:  "this is a test notification come from BE",
			},
			Token: tokens[0],
		}

		err := f.SendMessage(msg)

		if err != nil {
			t.Logf("error : %v", err.Error())
		}
	})
}

func TestSendMulticast(t *testing.T) {
	f, err := initFCM()
	assert.NoError(t, err)

	tokens, err := getTokens(fcmTokenPath)
	assert.NoError(t, err)

	t.Run("send multicast message", func(t *testing.T) {
		msg := &messaging.MulticastMessage{
			Notification: &messaging.Notification{
				Title: "test notification from BE",
				Body:  "this is a test notification come from BE",
			},
			Tokens: tokens,
		}

		err := f.SendMulticastMessage(msg)

		if err != nil {
			t.Logf("error : %v", err.Error())
		}
	})
}

func TestGetTokens(t *testing.T) {
	fclist, err := getTokens(fcmTokenPath)
	if err != nil {
		t.Logf("error get tokens : %v", err)
	}

	for idx, token := range fclist {
		t.Logf("token %d : %s", idx+1, token)
	}
}

func initFCM() (contract.Firebase, error) {
	ch, err := config.ConfigurationHead(configurationPath)
	if err != nil {
		return nil, err
	}

	fconf := ch.Configuration.Firebase

	if fconf.ServiceAccountKey == "" {
		return nil, errors.New("empty service account key")
	}

	f, err := Firebase(ch.Configuration)
	if err != nil {
		return nil, err
	}

	return f, nil
}

func getTokens(path string) ([]string, error) {
	flist := FCMList{}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, &flist); err != nil {
		return nil, err
	}

	return flist.RegistrationTokens, nil
}
