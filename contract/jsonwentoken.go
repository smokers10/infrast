package contract

import "github.com/stretchr/testify/mock"

type JsonWebTokenContractMock struct {
	Mock mock.Mock
}

type JsonWebTokenContract interface {
	Sign(payload map[string]interface{}) (token string, failure error)

	ParseToken(tokenString string) (payload map[string]interface{}, failure error)
}

func (m *JsonWebTokenContractMock) Sign(payload map[string]interface{}) (token string, failure error) {
	args := m.Mock.Called(payload)
	return args.String(0), args.Error(1)
}

func (m *JsonWebTokenContractMock) ParseToken(token string) (payload map[string]interface{}, failure error) {
	args := m.Mock.Called(token)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}
