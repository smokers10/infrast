package jsonwebtoken

import (
	"testing"
	"time"

	"github.com/smokers10/infrast/config"
	"github.com/stretchr/testify/assert"
)

func TestJsonWebToken(t *testing.T) {
	payload := map[string]interface{}{
		"type":    "admins",
		"user_id": 10,
		"iat":     time.Now().AddDate(0, 0, 7).Unix(),
	}

	// define mock config
	c := config.Configuration{
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
		assert.NotEmpty(t, p["type"].(string))
		assert.NotEmpty(t, p["user_id"].(float64))
		assert.NotEmpty(t, p["iat"].(float64))
		assert.Equal(t, "admins", p["type"].(string))
		assert.Equal(t, 10, int(p["user_id"].(float64)))
		assert.Equal(t, time.Now().AddDate(0, 0, 7).Unix(), int64(p["iat"].(float64)))
	})
}

func TestParsing(t *testing.T) {
	c := config.Configuration{
		Application: config.Application{
			Port:   ":8000",
			Secret: "abcdefg",
		},
	}

	jwt := JsonWebToken(&c)

	_, err := jwt.ParseToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.cThIIoDvwdueQB468K5xDc5633seEFoqwxjF_xSJyQQ")
	assert.Error(t, err)
	t.Logf("error : %s", err.Error())
}
