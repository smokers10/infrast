package contract

import (
	"github.com/midtrans/midtrans-go/coreapi"
	"github.com/midtrans/midtrans-go/iris"
	"github.com/midtrans/midtrans-go/snap"
	"github.com/stretchr/testify/mock"
)

type Midtrans interface {
	Core() coreapi.Client

	Snap() snap.Client

	Iris() iris.Client
}

type MidtransMock struct {
	Mock mock.Mock
}

func (m *MidtransMock) Core() coreapi.Client {
	args := m.Mock.Called()
	return args.Get(0).(coreapi.Client)
}

func (m *MidtransMock) Snap() snap.Client {
	args := m.Mock.Called()
	return args.Get(0).(snap.Client)
}

func (m *MidtransMock) Iris() iris.Client {
	args := m.Mock.Called()
	return args.Get(0).(iris.Client)
}
