package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/smokers10/infrast/contract"
	"golang.org/x/crypto/bcrypt"
)

type encryptionImplementation struct {
	Key []byte
}

// Decrypt implements contract.EncryptionContract.
func (i *encryptionImplementation) Decrypt(ciphertext string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(i.Key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

// Encrypt implements contract.EncryptionContract.
func (i *encryptionImplementation) Encrypt(plaintext string) (string, error) {
	byteMsg := []byte(plaintext)
	block, err := aes.NewCipher(i.Key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Compare implements contract.EncryptionContract
func (i *encryptionImplementation) Compare(plaintext string, hashed string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plaintext)); err != nil {
		return false
	}
	return true
}

// Hash implements contract.EncryptionContract
func (i *encryptionImplementation) Hash(plaintext string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(hashed)
}

func Encryption(key []byte) (contract.EncryptionContract, error) {
	keyLength := len(key)
	if keyLength != 16 && keyLength != 24 && keyLength != 32 {
		return nil, fmt.Errorf("key length must be 16, 24, or 32 bytes, but got %d", keyLength)
	}

	return &encryptionImplementation{Key: key}, nil
}
