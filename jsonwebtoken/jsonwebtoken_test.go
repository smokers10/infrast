package jsonwebtoken

import (
	"testing"

	"github.com/smokers10/go-infrastructure/config"
	"github.com/stretchr/testify/assert"
)

func TestJsonWebToken(t *testing.T) {
	payload := map[string]interface{}{
		"name": "john doe",
		"age":  24,
	}
	// define mock config
	c := config.Configuration{
		PostgreSQL: config.DatabasePostgreSQL{
			Host:                  "localhost",
			Port:                  5432,
			User:                  "testuser",
			Password:              "testpass",
			DBName:                "testdb",
			MaxOpenConnections:    10,
			MaxIdleConnections:    2,
			ConnectionMaxLifeTime: 10,
		},
		MongoDB: config.DatabaseMongoDB{
			URI:                "mongodb://testuser:testpass@localhost:27017/?authMechanism=SCRAM-SHA-1",
			MaxPool:            10,
			MinPool:            2,
			MaxIdleConnections: 1,
			DBName:             "testing",
		},
		Application: config.Application{
			Port:   ":8000",
			Secret: "abcdefg",
		},
	}

	jwt := JsonWebToken(&c)
	token, err := jwt.Sign(payload)

	t.Run("check sign token", func(t *testing.T) {
		assert.Empty(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("check parsing", func(t *testing.T) {
		p, err := jwt.ParseToken(token)

		assert.Empty(t, err)
		assert.NotEmpty(t, p["name"].(string))
		assert.NotEmpty(t, p["age"].(float64))
		assert.Equal(t, "john doe", p["name"].(string))
		assert.Equal(t, 24, int(p["age"].(float64)))
	})
}
