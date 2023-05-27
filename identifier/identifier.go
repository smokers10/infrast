package identifier

import (
	"github.com/google/uuid"
	"github.com/smokers10/go-infrastructure/contract"
)

type identifierImplementation struct{}

// MakeIdentifier implements contract.IdentfierContract
func (i *identifierImplementation) MakeIdentifier() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func Identifier() contract.IdentfierContract {
	return &identifierImplementation{}
}
