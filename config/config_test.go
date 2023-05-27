package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReader(t *testing.T) {
	c, err := Reader("config.yaml")
	if err != nil {
		t.Fatalf("error confg reader : %v\n", err.Error())
	}

	t.Run("application", func(t *testing.T) {
		app := c.Application
		assert.NotEmpty(t, app.Port)
		assert.NotEmpty(t, app.Secret)
	})

	t.Run("postgres", func(t *testing.T) {
		postgres := c.PostgreSQL
		assert.NotEmpty(t, postgres.ConnectionMaxLifeTime)
		assert.NotEmpty(t, postgres.DBName)
		assert.NotEmpty(t, postgres.Host)
		assert.NotEmpty(t, postgres.MaxIdleConnections)
		assert.NotEmpty(t, postgres.MaxOpenConnections)
		assert.NotEmpty(t, postgres.Password)
		assert.NotEmpty(t, postgres.Port)
		assert.NotEmpty(t, postgres.User)
	})

	t.Run("mongodb", func(t *testing.T) {
		mongodb := c.MongoDB
		assert.NotEmpty(t, mongodb.DBName)
		assert.NotEmpty(t, mongodb.MaxIdleConnections)
		assert.NotEmpty(t, mongodb.MaxPool)
		assert.NotEmpty(t, mongodb.MinPool)
		assert.NotEmpty(t, mongodb.URI)
	})

	t.Run("smtp", func(t *testing.T) {
		smtp := c.SMTP
		assert.NotEmpty(t, smtp.Host)
		assert.NotEmpty(t, smtp.Password)
		assert.NotEmpty(t, smtp.Username)
		assert.NotEmpty(t, smtp.Port)
		assert.NotEmpty(t, smtp.Sender)
	})
}
