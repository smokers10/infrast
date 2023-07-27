package head

import (
	"errors"
	"fmt"

	"github.com/common-nighthawk/go-figure"
	"github.com/sirupsen/logrus"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/smokers10/infrast/database"
	"github.com/smokers10/infrast/encryption"
	"github.com/smokers10/infrast/firebase"
	"github.com/smokers10/infrast/identifier"
	"github.com/smokers10/infrast/jsonwebtoken"
	"github.com/smokers10/infrast/lib"
	"github.com/smokers10/infrast/mailer"
	"github.com/smokers10/infrast/middleware"
	"github.com/smokers10/infrast/midtrans"
	tablestructurechecker "github.com/smokers10/infrast/table-structure-checker"
	templateprocessor "github.com/smokers10/infrast/template-processor"
	usermanagement "github.com/smokers10/infrast/user-management"
	usermanagementrepository "github.com/smokers10/infrast/user-management-repository"
	"github.com/smokers10/infrast/whatsapp"
)

type Module struct {
	DB                       contract.DatabaseContract
	Encryption               contract.EncryptionContract
	Identfier                contract.IdentfierContract
	JWT                      contract.JsonWebTokenContract
	Mailer                   contract.MailerContract
	TemplateProcessor        contract.TemplateProcessor
	UserManagementRepository contract.UserManagementRepository
	Midtrans                 contract.Midtrans
	Whatsapp                 contract.Whatsapp
	Firebase                 contract.Firebase
	Configuration            *config.Configuration
}

func Head(path string, encryption_key string) (*Module, error) {
	art := figure.NewColorFigure("INFRAST", "", "red", true)
	art.Print()
	fmt.Printf("CREATED BY : smokers10 \n\n")

	ch, err := config.ConfigurationHead(path)
	if err != nil {
		return nil, err
	}
	c := ch.Configuration
	logrus.Info("configuration loaded")

	key := []byte(encryption_key)
	encryption, err := encryption.Encryption(key)
	if err != nil {
		return nil, fmt.Errorf("error preparing encryption : %v", err)
	}

	if c.Application.Secret != "" {
		secret, err := encryption.Decrypt(c.Application.Secret)
		if err != nil {
			return nil, fmt.Errorf("error to read smtp password (plaintext not allowed): %v", err.Error())
		}
		c.Application.Secret = string(secret)
	}

	if c.PostgreSQL.Password != "" {
		postgresPassword, err := encryption.Decrypt(c.PostgreSQL.Password)
		if err != nil {
			return nil, fmt.Errorf("error to read postgre password (plaintext not allowed): %v", err.Error())
		}
		c.PostgreSQL.Password = string(postgresPassword)
	}

	if c.MongoDB.URI != "" {
		mongodbURI, err := encryption.Decrypt(c.MongoDB.URI)
		if err != nil {
			return nil, fmt.Errorf("error to read mongodb uri (plaintext not allowed): %v", err.Error())
		}

		c.MongoDB.URI = string(mongodbURI)
	}

	if c.SMTP.Password != "" {
		smtpPassword, err := encryption.Decrypt(c.SMTP.Password)
		if err != nil {
			return nil, fmt.Errorf("error to read smtp password (plaintext not allowed): %v", err.Error())
		}
		c.SMTP.Password = string(smtpPassword)
	}

	if c.Midtrans.ServerKey != "" {
		midtransServerKey, err := encryption.Decrypt(c.Midtrans.ServerKey)
		if err != nil {
			return nil, fmt.Errorf("error to read midtrans server key (plaintext not allowed): %v", err.Error())
		}
		c.Midtrans.ServerKey = string(midtransServerKey)
	}

	if c.Midtrans.IrisKey != "" {
		irisKey, err := encryption.Decrypt(c.Midtrans.IrisKey)
		if err != nil {
			return nil, fmt.Errorf("error to read midtrans iris key (plaintext not allowed): %v", err.Error())
		}
		c.Midtrans.IrisKey = string(irisKey)
	}

	if c.Whatsapp.AuthToken != "" {
		authToken, err := encryption.Decrypt(c.Whatsapp.AuthToken)
		if err != nil {
			return nil, fmt.Errorf("error to read whatsapp auth token (plaintext not allowed): %v", err.Error())
		}
		c.Whatsapp.AuthToken = authToken
	}

	if c.Firebase.ServiceAccountKey != "" {
		sak, err := encryption.Decrypt(c.Firebase.ServiceAccountKey)
		if err != nil {
			return nil, fmt.Errorf("error to read whatsapp auth token (plaintext not allowed): %v", err.Error())
		}
		c.Firebase.ServiceAccountKey = sak
	}

	modules := Module{
		Encryption:        encryption,
		Identfier:         identifier.Identifier(c),
		JWT:               jsonwebtoken.JsonWebToken(c),
		TemplateProcessor: templateprocessor.TemplateProccessor(),
		Configuration:     c,
	}

	if c.Midtrans.ServerKey != "" || c.Midtrans.IrisKey != "" {
		midtrans, err := midtrans.Midtrans(c)
		if err != nil {
			return nil, fmt.Errorf("error midtrans : %v", err.Error())
		}

		modules.Midtrans = midtrans
	} else {
		logrus.Warning("Midtrans Disabled")
	}

	if c.Whatsapp.AuthToken != "" && c.Whatsapp.SID != "" {
		whatsapp, err := whatsapp.Whatsapp(c)
		if err != nil {
			return nil, fmt.Errorf("error whatsapp : %v", err.Error())
		}

		modules.Whatsapp = whatsapp
	} else {
		logrus.Warning("Whatsapp Disabled")
	}

	if c.Firebase.ServiceAccountKey != "" {
		firebase, err := firebase.Firebase(c)
		if err != nil {
			return nil, fmt.Errorf("error firebase : %v", err.Error())
		}

		modules.Firebase = firebase
	} else {
		logrus.Warning("Firebase Disabled")
	}

	if c.SMTP.Host != "" && c.SMTP.Password != "" {
		mailer := mailer.Mailer(c)
		modules.Mailer = mailer
	} else {
		logrus.Warning("SMTP disabled")
	}

	database := database.Database(c)
	sql, err := database.PosgresSQL()
	if err != nil {
		return nil, fmt.Errorf("error call postgre db : %v", err.Error())
	}
	modules.UserManagementRepository = usermanagementrepository.UserManagementRepository(sql)
	modules.DB = database

	logrus.Info("modules ready")

	checkerRepo := tablestructurechecker.TableStructureCheckerRepository(sql)
	checker := tablestructurechecker.TableStructureChecker(checkerRepo)
	checkResult, err := checker.StructureChecker(&c.UserManagement)
	if err != nil {
		return nil, err
	}

	if len(checkResult) != 0 {
		lib.CheckResultLogFormat(checkResult)
		return nil, errors.New("user management TSC error")
	} else {
		logrus.Info("user management ready!")
	}

	logrus.Info("Infrast OK!")

	return &modules, nil
}

func (h *Module) Middleware(userType string) (contract.Middleware, error) {
	m, err := middleware.Middleware(&h.Configuration.UserManagement, h.UserManagementRepository, h.JWT, userType)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (h *Module) UserManagement(userType string) (contract.UserManagement, error) {
	UM, err := usermanagement.UserManagement(h.Configuration, h.UserManagementRepository, h.Identfier, h.Encryption, h.JWT, h.Mailer, h.Whatsapp, h.TemplateProcessor, userType)
	if err != nil {
		return nil, err
	}

	return UM, nil
}
