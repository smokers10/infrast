package head

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHead(t *testing.T) {
	head, err := Head("config.yaml", "first-man-of-war")
	assert.NoError(t, err)

	c := head.Configuration
	t.Logf("application secret : %s", c.Application.Secret)
	t.Logf("postgres password : %s", c.PostgreSQL.Password)
	t.Logf("mongodb uri : %s", c.MongoDB.URI)
	t.Logf("smtp password : %s", c.SMTP.Password)
	t.Logf("midtrans server key : %s", c.Midtrans.ServerKey)
	t.Logf("midtrans iris key : %s", c.Midtrans.IrisKey)
	t.Logf("whatsapp auth token : %s", c.Whatsapp.AuthToken)
	decodedKey, err := base64.StdEncoding.DecodeString(c.Firebase.ServiceAccountKey)
	assert.NoError(t, err)
	t.Logf("firebase service account key : %s", decodedKey)

	t.Run("check user management", func(t *testing.T) {
		UM, err := head.UserManagement("user")
		assert.NoError(t, err)
		assert.NotNil(t, UM)
	})

	t.Run("check middleware", func(t *testing.T) {
		middleware, err := head.Middleware("user")
		assert.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}
