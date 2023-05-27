package contract

import "github.com/stretchr/testify/mock"

type IdentfierContractMock struct {
	Mock mock.Mock
}

type IdentfierContract interface {
	MakeIdentifier() (string, error)
}

func (m *IdentfierContractMock) MakeIdentifier() (string, error) {
	args := m.Mock.Called()
	return args.String(0), args.Error(1)
}
