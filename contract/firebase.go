package contract

import (
	"firebase.google.com/go/messaging"
	"github.com/stretchr/testify/mock"
)

type Firebase interface {
	SendMessage(data *messaging.Message) error

	SendMulticastMessage(data *messaging.MulticastMessage) error
}

type FirebaseMock struct {
	Mock mock.Mock
}

func (m *FirebaseMock) SendMessage(data *messaging.Message) error {
	args := m.Mock.Called(data)
	return args.Error(0)
}

func (m *FirebaseMock) SendMulticastMessage(data *messaging.MulticastMessage) error {
	args := m.Mock.Called(data)
	return args.Error(0)
}
