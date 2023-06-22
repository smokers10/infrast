package identifier

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/smokers10/go-infrastructure/config"
	"github.com/smokers10/go-infrastructure/contract"
	"github.com/xlzd/gotp"
)

type identifierImplementation struct {
	Config *config.Application
}

// GenerateOTP implements contract.IdentfierContract
func (i *identifierImplementation) GenerateOTP() (string, error) {
	TOTP := gotp.NewDefaultTOTP(i.Config.Secret)

	if i.Config.Secret == "" {
		return "", errors.New("application secret not exists")
	}

	return TOTP.At(time.Now().Unix()), nil
}

// MakeIdentifier implements contract.IdentfierContract
func (i *identifierImplementation) MakeIdentifier() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func Identifier(config *config.Configuration) contract.IdentfierContract {
	return &identifierImplementation{Config: &config.Application}
}
