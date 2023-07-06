package head

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHead(t *testing.T) {
	head, err := Head("config.yaml")
	assert.NoError(t, err)

	t.Run("check user management", func(t *testing.T) {
		UM, err := head.UserManagement("admin")
		assert.NoError(t, err)
		assert.NotNil(t, UM)
	})

	t.Run("check middleware", func(t *testing.T) {
		middleware, err := head.Middleware("admin")
		assert.NoError(t, err)
		assert.NotNil(t, middleware)
	})
}
