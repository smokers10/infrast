package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReader(t *testing.T) {
	c, err := ConfigurationHead("configuration.yaml")
	if err != nil {
		t.Fatalf("error config reader : %v\n", err.Error())
	}

	t.Run("application", func(t *testing.T) {
		app := c.Configuration.Application
		assert.NotEmpty(t, app.Port)
		assert.NotEmpty(t, app.Secret)
		assert.NotEmpty(t, app.UserManagementInstance)
		assert.NotEmpty(t, app.UserStorageInstance)
		t.Logf("umpginstace : %s", app.UserManagementInstance)
	})

	t.Run("postgres", func(t *testing.T) {
		postgres := c.Configuration.PostgreSQL
		for _, v := range postgres {
			assert.NotEmpty(t, v.Label)
			assert.NotEmpty(t, v.ConnectionMaxLifeTime)
			assert.NotEmpty(t, v.DBName)
			assert.NotEmpty(t, v.Host)
			assert.NotEmpty(t, v.MaxIdleConnections)
			assert.NotEmpty(t, v.MaxOpenConnections)
			assert.NotEmpty(t, v.Password)
			assert.NotEmpty(t, v.Port)
			assert.NotEmpty(t, v.User)
		}
	})

	t.Run("mongodb", func(t *testing.T) {
		mongodb := c.Configuration.MongoDB
		for _, v := range mongodb {
			assert.NotEmpty(t, v.Label)
			assert.NotEmpty(t, v.DBName)
			assert.NotEmpty(t, v.MaxIdleConnections)
			assert.NotEmpty(t, v.MaxPool)
			assert.NotEmpty(t, v.MinPool)
			assert.NotEmpty(t, v.URI)
		}
	})

	t.Run("smtp", func(t *testing.T) {
		smtp := c.Configuration.SMTP
		assert.NotEmpty(t, smtp.Host)
		assert.NotEmpty(t, smtp.Password)
		assert.NotEmpty(t, smtp.Username)
		assert.NotEmpty(t, smtp.Port)
		assert.NotEmpty(t, smtp.Sender)
	})

	t.Run("midtrans", func(t *testing.T) {
		midtrans := c.Configuration.Midtrans
		assert.NotEmpty(t, midtrans.ServerKey)
		assert.NotEmpty(t, midtrans.EnabledPayments)
		assert.NotEmpty(t, midtrans.IrisKey)
		assert.NotEmpty(t, midtrans.Environment)
		for idx, v := range midtrans.EnabledPayments {
			t.Logf("index %v : %v\n", idx+1, v)
		}
	})

	t.Run("whatsapp", func(t *testing.T) {
		whatsapp := c.Configuration.Whatsapp
		assert.NotEmpty(t, whatsapp.SID)
		assert.NotEmpty(t, whatsapp.AuthToken)
		assert.NotEmpty(t, whatsapp.Sender)
	})

	t.Run("firebase", func(t *testing.T) {
		firebase := c.Configuration.Firebase
		assert.NotEmpty(t, firebase.ServiceAccountKey)
	})
}
