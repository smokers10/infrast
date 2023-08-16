package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const isBase64 = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$"

func TestHashing(t *testing.T) {
	plaintext := "testhased"
	key := "first-man-of-war"
	e, err := Encryption([]byte(key))
	assert.NoError(t, err)

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

func TestEncryptDecryptMessage(t *testing.T) {
	plaintext := "sick feeling is you!"
	key := "yutgtredswqaswer"
	e, err := Encryption([]byte(key))
	assert.NoError(t, err)

	encrypted, err := e.Encrypt(plaintext)
	require.Nil(t, err)
	require.Regexp(t, isBase64, encrypted)

	decrypted, err := e.Decrypt(encrypted)
	require.Nil(t, err)
	require.Equal(t, plaintext, decrypted)

	t.Logf("encrypted : %s", encrypted)
	t.Logf("decrypted : %s", decrypted)
}

func TestDecrypt(t *testing.T) {
	key := "TPnlimaXPSau9LG7cmLcbpzeyVjxlE2p"
	ciphers := []string{
		"Y92GrkgRIhzpiMusxuV+n2LHnl1ExLwzBV0CQbevGUhYc5EDKz1lf0Y=",
		"U1v8y/yxpjBBDHKFH0EqM/wAeY6xhcHhI/w=",
		"9qwEZWOfjPdwwrtUhJkZWWWjtQFbl1VygBQegVsMPIWoCGUImR/nQ7ARdkN9CM8p0UK9NvYhPeKQzdUBMN6qsmvc1hZ/btDEybwtOSBiclk8aeA/h+U=",
		"glHbQWu95fe5GGZieGXSr+Y5b10vP57GBMrbcWL3Kqk=",
		"8ZmwHN4668y7XGhIOQ73eXYTNMTfPs9PQCVyHz1cdGS14Ys=",
	}

	e, err := Encryption([]byte(key))
	assert.NoError(t, err)

	for _, v := range ciphers {
		decrypted, err := e.Decrypt(v)
		require.Nil(t, err)

		t.Logf("decrypted : %s", decrypted)
	}
}

func TestDecryptPT2(t *testing.T) {
	key := "first-man-of-war"
	ciphers := []string{
		"3mp3OVuLVCJkb6ZWQiEu04GpKBzsu+MpOW5+QCNxG8A+yCVlAg==",
		"xT1fvQJEcZgFy6TLb1iaFlrkxYJxK8bbzubV",
		"dx70Bg/LXzieAFuqyjAA4XIOtihSrEUg0cUbTLI=",
	}

	e, err := Encryption([]byte(key))
	assert.NoError(t, err)

	for _, v := range ciphers {
		decrypted, err := e.Decrypt(v)
		require.Nil(t, err)

		t.Logf("decrypted : %s", decrypted)
	}
}
