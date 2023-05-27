package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryption(t *testing.T) {
	plaintext := "testhased"
	e := Encryption()

	t.Run("TEST HASH", func(t *testing.T) {
		hashed := e.Hash(plaintext)

		assert.NotEmpty(t, hashed)
		t.Log(hashed)

		t.Run("TEST COMPARE", func(t *testing.T) {
			correct := e.Compare(plaintext, hashed)
			wrong := e.Compare("betrayal betray the betrayer", hashed)
			assert.True(t, correct)
			assert.False(t, wrong)
		})
	})
}
