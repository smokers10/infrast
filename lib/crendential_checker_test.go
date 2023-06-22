package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredentialChecker(t *testing.T) {
	t.Run("is email", func(t *testing.T) {
		credType := CredentialChecker("johndoe@gmail.com")
		assert.Equal(t, "email", credType)
	})

	t.Run("is phone", func(t *testing.T) {
		credType := CredentialChecker("08112123255")
		assert.Equal(t, "phone", credType)
	})

	t.Run("is uncertain", func(t *testing.T) {
		credType := CredentialChecker("08112123@255")
		assert.Equal(t, "uncertain", credType)
	})
}
