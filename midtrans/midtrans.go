package midtrans

import (
	"errors"

	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"
	"github.com/midtrans/midtrans-go/iris"
	"github.com/midtrans/midtrans-go/snap"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
)

type midtransImpl struct {
	config     *config.Midtrans
	enviroment midtrans.EnvironmentType
}

// Core implements contract.Midtrans.
func (i *midtransImpl) Core() coreapi.Client {
	var c = coreapi.Client{}
	c.New(i.config.ServerKey, i.enviroment)

	return c
}

// Iris implements contract.Midtrans.
func (i *midtransImpl) Iris() iris.Client {
	var ir = iris.Client{}
	ir.New(i.config.IrisKey, i.enviroment)

	return ir
}

// Snap implements contract.Midtrans.
func (i *midtransImpl) Snap() snap.Client {
	var s = snap.Client{}
	s.New(i.config.ServerKey, i.enviroment)

	return s
}

func Midtrans(config *config.Configuration) (contract.Midtrans, error) {
	midtransConfig := config.Midtrans
	var environment midtrans.EnvironmentType

	if (midtransConfig.Environment != "production") && (midtransConfig.Environment != "sandbox") {
		return nil, errors.New("midtrans enviroment only accept production or sandbox")
	}

	if midtransConfig.Environment == "production" {
		environment = midtrans.Production
	}

	if midtransConfig.Environment == "sandbox" {
		environment = midtrans.Sandbox
	}

	return &midtransImpl{config: &midtransConfig, enviroment: environment}, nil
}
