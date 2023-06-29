package head

import (
	"errors"
	"fmt"

	"github.com/smokers10/go-infrastructure/config"
	"github.com/smokers10/go-infrastructure/contract"
	"github.com/smokers10/go-infrastructure/database"
	"github.com/smokers10/go-infrastructure/encryption"
	"github.com/smokers10/go-infrastructure/identifier"
	"github.com/smokers10/go-infrastructure/jsonwebtoken"
	"github.com/smokers10/go-infrastructure/lib"
	"github.com/smokers10/go-infrastructure/mailer"
	tablestructurechecker "github.com/smokers10/go-infrastructure/table-structure-checker"
	templateprocessor "github.com/smokers10/go-infrastructure/template-processor"
)

type ModuleHeader struct {
	DB                contract.DatabaseContract
	Encryption        contract.EncryptionContract
	Identfier         contract.IdentfierContract
	JWT               contract.JsonWebTokenContract
	Mailer            contract.MailerContract
	TemplateProcessor contract.TemplateProcessor
	Configuration     *config.Configuration
}

func Head(path string) (*ModuleHeader, error) {
	ch := config.ConfigurationHead()
	config, err := ch.Read(path)
	if err != nil {
		return nil, err
	}

	result := ModuleHeader{
		DB:                database.Database(config),
		Encryption:        encryption.Encryption(),
		Identfier:         identifier.Identifier(config),
		JWT:               jsonwebtoken.JsonWebToken(config),
		Mailer:            mailer.Mailer(config),
		TemplateProcessor: templateprocessor.TemplateProccessor(),
		Configuration:     config,
	}

	sql, err := result.DB.PosgresSQL()
	if err != nil {
		return nil, fmt.Errorf("error call postgre db : %v", err.Error())
	}

	checkerRepo := tablestructurechecker.TableStructureCheckerRepository(sql)
	checker := tablestructurechecker.TableStructureChecker(checkerRepo)
	checkResult, err := checker.StructureChecker(&config.UserManagement)
	if err != nil {
		return nil, err
	}

	if len(checkResult) != 0 {
		lib.CheckResultLogFormat(checkResult)
		return nil, errors.New("user management TSC error")
	}

	return &result, nil
}
