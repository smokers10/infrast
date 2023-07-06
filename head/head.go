package head

import (
	"errors"
	"fmt"

	"github.com/common-nighthawk/go-figure"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/smokers10/infrast/database"
	"github.com/smokers10/infrast/encryption"
	"github.com/smokers10/infrast/identifier"
	"github.com/smokers10/infrast/jsonwebtoken"
	"github.com/smokers10/infrast/lib"
	"github.com/smokers10/infrast/mailer"
	"github.com/smokers10/infrast/middleware"
	tablestructurechecker "github.com/smokers10/infrast/table-structure-checker"
	templateprocessor "github.com/smokers10/infrast/template-processor"
	usermanagement "github.com/smokers10/infrast/user-management"
	usermanagementrepository "github.com/smokers10/infrast/user-management-repository"
)

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

func Head(path string) (*module, error) {
	art := figure.NewColorFigure("INFRAST", "", "red", true)
	art.Print()
	fmt.Printf("CREATED BY : smokers10 \n\n")

	fmt.Println("Phase 1 - Load Configration File")
	ch := config.ConfigurationHead()
	config, err := ch.Read(path)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Phase 1 OK!\n\n")

	fmt.Println("Phase 2 - Prepare Database")
	database := database.Database(config)
	sql, err := database.PosgresSQL()
	if err != nil {
		return nil, fmt.Errorf("error call postgre db : %v", err.Error())
	}
	fmt.Printf("Phase 2 OK!\n\n")

	fmt.Println("Phase 3 - Prepare Modules")
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
	fmt.Printf("Phase 4 OK!\n\n")

	fmt.Println("Phase 4 - Table Structure Checking")
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
	fmt.Printf("Phase 4 OK!\n")

	return &modules, nil
}

func (h *module) Middleware(userType string) (contract.Middleware, error) {
	m, err := middleware.Middleware(&h.Configuration.UserManagement, h.UserManagementRepository, h.JWT, userType)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (h *module) UserManagement(userType string) (contract.UserManagement, error) {
	UM, err := usermanagement.UserManagement(h.Configuration, h.UserManagementRepository, h.Identfier, h.Encryption, h.JWT, h.Mailer, h.TemplateProcessor, userType)
	if err != nil {
		return nil, err
	}

	return UM, nil
}
