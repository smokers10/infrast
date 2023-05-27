package contract

import "github.com/stretchr/testify/mock"

type EncryptionContractMock struct {
	Mock mock.Mock
}

type EncryptionContract interface {
	Hash(plaintext string) string

	Compare(plaintext string, hashed string) bool
}

func (m *EncryptionContractMock) Hash(plaintext string) string {
	args := m.Mock.Called(plaintext)
	return args.String(0)
}

func (m *EncryptionContractMock) Compare(plaintext string, hashed string) bool {
	args := m.Mock.Called(plaintext, hashed)
	return args.Bool(0)
}
