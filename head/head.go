package head

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/smokers10/infrast/database"
	"github.com/smokers10/infrast/encryption"
	"github.com/smokers10/infrast/firebase"
	"github.com/smokers10/infrast/identifier"
	"github.com/smokers10/infrast/jsonwebtoken"
	"github.com/smokers10/infrast/mailer"
	"github.com/smokers10/infrast/midtrans"
	templateprocessor "github.com/smokers10/infrast/template-processor"
	"github.com/smokers10/infrast/whatsapp"
)

type Module struct {
	DB                contract.DatabaseContract
	Encryption        contract.EncryptionContract
	Identfier         contract.IdentfierContract
	JWT               contract.JsonWebTokenContract
	Mailer            contract.MailerContract
	TemplateProcessor contract.TemplateProcessor
	Midtrans          contract.Midtrans
	Whatsapp          contract.Whatsapp
	Firebase          contract.Firebase
	Configuration     *config.Configuration
}

func Head(path string, encryption_key string) (*Module, error) {
	// read configuration
	ch, err := config.ConfigurationHead(path)
	if err != nil {
		return nil, err
	}
	c := ch.Configuration

	// read encrypted confugration value and assign to 'c' variable
	key := []byte(encryption_key)
	encryption, err := encryption.Encryption(key)
	if err != nil {
		return nil, fmt.Errorf("error preparing encryption : %v", err)
	}
	nc, err := readEncryptedConfig(c, encryption)
	if err != nil {
		return nil, err
	}
	c = nc

	// decalaration of infrast modules
	modules := Module{
		Encryption:        encryption,
		Identfier:         identifier.Identifier(c),
		JWT:               jsonwebtoken.JsonWebToken(c),
		TemplateProcessor: templateprocessor.TemplateProccessor(),
		DB:                database.Database(c),
		Configuration:     c,
	}

	if c.Midtrans.ServerKey != "" || c.Midtrans.IrisKey != "" {
		midtrans, err := midtrans.Midtrans(c)
		if err != nil {
			return nil, fmt.Errorf("error midtrans : %v", err.Error())
		}

		modules.Midtrans = midtrans
	}

	if c.Whatsapp.AuthToken != "" && c.Whatsapp.SID != "" {
		whatsapp, err := whatsapp.Whatsapp(c)
		if err != nil {
			return nil, fmt.Errorf("error whatsapp : %v", err.Error())
		}

		modules.Whatsapp = whatsapp
	}

	if c.Firebase.ServiceAccountKey != "" {
		firebase, err := firebase.Firebase(c)
		if err != nil {
			return nil, fmt.Errorf("error firebase : %v", err.Error())
		}

		modules.Firebase = firebase
	}

	if c.SMTP.Host != "" && c.SMTP.Password != "" {
		mailer := mailer.Mailer(c)
		modules.Mailer = mailer
	}

	logrus.Info("Infrast OK!")
	return &modules, nil
}

func readEncryptedConfig(c *config.Configuration, encryption contract.EncryptionContract) (*config.Configuration, error) {
	if c.Application.Secret != "" {
		secret, err := encryption.Decrypt(c.Application.Secret)
		if err != nil {
			return nil, fmt.Errorf("error to read application secret: %v", err.Error())
		}
		c.Application.Secret = string(secret)
	}

	for i := 0; i < len(c.PostgreSQL); i++ {
		if c.PostgreSQL[i].Password != "" {
			postgresPassword, err := encryption.Decrypt(c.PostgreSQL[i].Password)
			if err != nil {
				return nil, fmt.Errorf("error to read postgre password: %v", err.Error())
			}
			c.PostgreSQL[i].Password = string(postgresPassword)
		}
	}

	for i := 0; i < len(c.MongoDB); i++ {
		if c.MongoDB[i].URI != "" {
			mongodbURI, err := encryption.Decrypt(c.MongoDB[i].URI)
			if err != nil {
				return nil, fmt.Errorf("error to read mongodb uri: %v", err.Error())
			}

			c.MongoDB[i].URI = string(mongodbURI)
		}
	}

	if c.SMTP.Password != "" {
		smtpPassword, err := encryption.Decrypt(c.SMTP.Password)
		if err != nil {
			return nil, fmt.Errorf("error to read smtp password: %v", err.Error())
		}
		c.SMTP.Password = string(smtpPassword)
	}

	if c.Midtrans.ServerKey != "" {
		midtransServerKey, err := encryption.Decrypt(c.Midtrans.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("error to read midtrans server key: %v", err.Error())
		}
		c.Midtrans.ServerKey = string(midtransServerKey)
	}

	if c.Midtrans.IrisKey != "" {
		irisKey, err := encryption.Decrypt(c.Midtrans.IrisKey)
		if err != nil {
			return nil, fmt.Errorf("error to read midtrans iris key: %v", err.Error())
		}
		c.Midtrans.IrisKey = string(irisKey)
	}

	if c.Whatsapp.AuthToken != "" {
		authToken, err := encryption.Decrypt(c.Whatsapp.AuthToken)
		if err != nil {
			return nil, fmt.Errorf("error to read whatsapp auth token: %v", err.Error())
		}
		c.Whatsapp.AuthToken = authToken
	}

	if c.Firebase.ServiceAccountKey != "" {
		ServiceAccountKey, err := encryption.Decrypt(c.Firebase.ServiceAccountKey)
		if err != nil {
			return nil, fmt.Errorf("error to read whatsapp auth token: %v", err.Error())
		}
		c.Firebase.ServiceAccountKey = ServiceAccountKey
	}

	return c, nil
}
