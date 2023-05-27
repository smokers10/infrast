package encryption

import (
	"github.com/smokers10/go-infrastructure/contract"
	"golang.org/x/crypto/bcrypt"
)

type encryptionImplementation struct{}

// Compare implements contract.EncryptionContract
func (*encryptionImplementation) Compare(plaintext string, hashed string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plaintext)); err != nil {
		return false
	}
	return true
}

// Hash implements contract.EncryptionContract
func (*encryptionImplementation) Hash(plaintext string) string {
	hashed, _ := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(hashed)
}

func Encryption() contract.EncryptionContract {
	return &encryptionImplementation{}
}
