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
	"github.com/smokers10/go-infrastructure/middleware"
	tablestructurechecker "github.com/smokers10/go-infrastructure/table-structure-checker"
	templateprocessor "github.com/smokers10/go-infrastructure/template-processor"
	usermanagement "github.com/smokers10/go-infrastructure/user-management"
	usermanagementrepository "github.com/smokers10/go-infrastructure/user-management-repository"
)

type Head struct {
	Module module
}

type module struct {
	DB                       contract.DatabaseContract
	Encryption               contract.EncryptionContract
	Identfier                contract.IdentfierContract
	JWT                      contract.JsonWebTokenContract
	Mailer                   contract.MailerContract
	TemplateProcessor        contract.TemplateProcessor
	UserManagementRepository contract.UserManagementRepository
	Configuration            *config.Configuration
}

func (h *Head) Initialize(path string) (*module, error) {
	ch := config.ConfigurationHead()
	config, err := ch.Read(path)
	if err != nil {
		return nil, err
	}

	database := database.Database(config)
	sql, err := database.PosgresSQL()
	if err != nil {
		return nil, fmt.Errorf("error call postgre db : %v", err.Error())
	}

	modules := module{
		DB:                       database,
		Encryption:               encryption.Encryption(),
		Identfier:                identifier.Identifier(config),
		JWT:                      jsonwebtoken.JsonWebToken(config),
		Mailer:                   mailer.Mailer(config),
		TemplateProcessor:        templateprocessor.TemplateProccessor(),
		UserManagementRepository: usermanagementrepository.UserManagementRepository(sql),
		Configuration:            config,
	}

	h.Module = modules

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

	return &modules, nil
}

func (h *Head) Middleware(userType string) (contract.Middleware, error) {
	m, err := middleware.Middleware(&h.Module.Configuration.UserManagement, h.Module.UserManagementRepository, h.Module.JWT, userType)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (h *Head) UserManagement(userType string) (contract.UserManagement, error) {
	UM, err := usermanagement.UserManagement(h.Module.Configuration, h.Module.UserManagementRepository, h.Module.Identfier, h.Module.Encryption, h.Module.JWT, h.Module.Mailer, h.Module.TemplateProcessor, userType)
	if err != nil {
		return nil, err
	}

	return UM, nil
}
