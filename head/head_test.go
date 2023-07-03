package head

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHead(t *testing.T) {
	head, err := Head().Initialize("config.yaml")
	assert.NoError(t, err)

	t.Run("head middleware", func(t *testing.T) {
		_, err := head.UserManagement("admin")
		assert.NoError(t, err)
	})
}
