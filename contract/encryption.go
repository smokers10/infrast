package contract

import "github.com/stretchr/testify/mock"

type EncryptionContractMock struct {
	Mock mock.Mock
}

type EncryptionContract interface {
	Hash(plaintext string) string

	Compare(plaintext string, hashed string) bool

	Encrypt(plaintext string) (string, error)

	Decrypt(ciphertext string) (string, error)
}

func (m *EncryptionContractMock) Hash(plaintext string) string {
	args := m.Mock.Called(plaintext)
	return args.String(0)
}

func (m *EncryptionContractMock) Compare(plaintext string, hashed string) bool {
	args := m.Mock.Called(plaintext, hashed)
	return args.Bool(0)
}

func (m *EncryptionContractMock) Encrypt(plaintext string) (string, error) {
	args := m.Mock.Called(plaintext)
	return args.String(0), args.Error(1)
}

func (m *EncryptionContractMock) Decrypt(ciphertext string) (string, error) {
	args := m.Mock.Called(ciphertext)
	return args.String(0), args.Error(1)
}
