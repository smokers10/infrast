package contract

import (
	"github.com/stretchr/testify/mock"
)

type Whatsapp interface {
	SendMessage(message string, to string) error
}

type WhatsappMock struct {
	Mock mock.Mock
}

func (m *WhatsappMock) SendMessage(message string) error {
	args := m.Mock.Called(message)
	return args.Error(0)
}
