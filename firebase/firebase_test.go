package firebase

import (
	"testing"

	"firebase.google.com/go/messaging"
	"github.com/smokers10/infrast/config"
	"github.com/stretchr/testify/assert"
)

func TestSend(t *testing.T) {
	ch, err := config.ConfigurationHead("config.yaml")
	assert.NoError(t, err)
	fconf := ch.Configuration.Firebase
	assert.NotEmpty(t, fconf.ServiceAccountKey)

	f, err := Firebase(ch.Configuration)
	assert.NoError(t, err)

	t.Run("send single message", func(t *testing.T) {
		err := f.SendMessage(&messaging.Message{
			Notification: &messaging.Notification{
				Title: "test notification",
				Body:  "this is a test notification",
			},
			Token: "lpi-test-2023",
			Data:  make(map[string]string),
		})

		if err != nil {
			t.Logf("error : %v", err.Error())
		}
	})
}
