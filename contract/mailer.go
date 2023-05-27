package contract

import "github.com/stretchr/testify/mock"

type MailerContractMock struct {
	Mock mock.Mock
}

type MailerContract interface {
	Send(reciever []string, subject string, template string) error
}

func (m *MailerContractMock) Send(reciever []string, subject string, template string) error {
	args := m.Mock.Called(reciever, subject, template)
	return args.Error(0)
}
