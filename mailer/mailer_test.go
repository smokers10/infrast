package mailer

import (
	"testing"

	"github.com/smokers10/infrast/config"
	"github.com/stretchr/testify/assert"
)

func TestMailer(t *testing.T) {
	c, err := config.ConfigurationHead("config.yaml")
	if err != nil {
		t.Fatalf("Error config reader : %v\n", err.Error())
	}

	smtp := Mailer(c.Configuration)

	err = smtp.Send([]string{"lpiexecutive@gmail.com"}, "good morning!", "hey good morning budy!")
	assert.Empty(t, err)
}
