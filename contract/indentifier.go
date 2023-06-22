package contract

import "github.com/stretchr/testify/mock"

type IdentfierContract interface {
	MakeIdentifier() (string, error)

	GenerateOTP() (string, error)
}

type IdentfierContractMock struct {
	Mock mock.Mock
}

func (m *IdentfierContractMock) MakeIdentifier() (string, error) {
	args := m.Mock.Called()
	return args.String(0), args.Error(1)
}

func (m *IdentfierContractMock) GenerateOTP() (string, error) {
	args := m.Mock.Called()
	return args.String(0), args.Error(1)
}
