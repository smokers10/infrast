package tablestructurechecker

import (
	"fmt"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
)

type tableStructureCheckerImplementation struct {
	CheckerRepository contract.TableStructureCheckerRepository
}

// StructureChecker implements contract.TableStructureChecker.
func (i *tableStructureCheckerImplementation) StructureChecker(umc *config.UserManagementConfig) (result []contract.CheckResult, failure error) {
	tables := tableToCheck(umc)
	userTables := userStorageTableToCheck(umc)

	// user management TSC
	for _, tableName := range tables {
		dump := contract.CheckResult{}
		dump.TableName = tableName

		column, err := i.CheckerRepository.StructureGetter(tableName, false)
		if err != nil {
			return nil, fmt.Errorf("error on accessing table %s with error %v", tableName, err.Error())
		}

		if tableName == umc.Login.TableName {
			loginCheck := loginCheck(column, &umc.Login)
			if len(loginCheck) != 0 {
				dump.Mismatch = append(dump.Mismatch, loginCheck...)
			}
		}

		if tableName == umc.Registration.TableName {
			registrationCheck := registrationCheck(column, &umc.Registration)
			if len(registrationCheck) != 0 {
				dump.Mismatch = append(dump.Mismatch, registrationCheck...)
			}
		}

		if tableName == umc.ResetPassword.TableName {
			resetPasswordCheck := resetPasswordCheck(column, &umc.ResetPassword)
			if len(resetPasswordCheck) != 0 {
				dump.Mismatch = append(dump.Mismatch, resetPasswordCheck...)
			}
		}

		if tableName == umc.UserDevice.TableName {
			userDeviceCheck := userDeviceCheck(column, &umc.UserDevice)
			if len(userDeviceCheck) != 0 {
				dump.Mismatch = append(dump.Mismatch, userDeviceCheck...)
			}
		}

		if tableName == umc.UserFCMToken.TableName {
			userFCMCheck := userFCMCheck(column, &umc.UserFCMToken)
			if len(userFCMCheck) != 0 {
				dump.Mismatch = append(dump.Mismatch, userFCMCheck...)
			}
		}

		if len(dump.Mismatch) != 0 {
			result = append(result, dump)
			dump = contract.CheckResult{}
		}
	}

	// user storage TSC
	for _, userTable := range userTables {
		dump := contract.CheckResult{}
		dump.TableName = userTable

		column, err := i.CheckerRepository.StructureGetter(userTable, true)
		if err != nil {
			return nil, fmt.Errorf("error on accessing user storage %s with error %v", userTable, err.Error())
		}

		for idx, v := range umc.Users {
			if v.UserTable == userTable {
				userCredentialCheck := userCredentailCheck(column, &umc.Users[idx])
				if len(userCredentialCheck) != 0 {
					dump.Mismatch = append(dump.Mismatch, userCredentialCheck...)
				}
			}
		}

		if len(dump.Mismatch) != 0 {
			result = append(result, dump)
			dump = contract.CheckResult{}
		}
	}

	return result, nil
}

// func to give table to check dynamicaly
func tableToCheck(umc *config.UserManagementConfig) []string {
	tableToCheck := []string{}

	if umc.Login.TableName != "" {
		tableToCheck = append(tableToCheck, umc.Login.TableName)
	}

	if umc.Registration.TableName != "" {
		tableToCheck = append(tableToCheck, umc.Registration.TableName)
	}

	if umc.ResetPassword.TableName != "" {
		tableToCheck = append(tableToCheck, umc.ResetPassword.TableName)
	}

	if umc.UserDevice.TableName != "" {
		tableToCheck = append(tableToCheck, umc.UserDevice.TableName)
	}

	if umc.UserFCMToken.TableName != "" {
		tableToCheck = append(tableToCheck, umc.UserFCMToken.TableName)
	}

	return tableToCheck
}

func userStorageTableToCheck(umc *config.UserManagementConfig) []string {
	tableToCheck := []string{}

	if len(umc.Users) != 0 {
		for _, v := range umc.Users {
			tableToCheck = append(tableToCheck, v.UserTable)
		}
	}

	return tableToCheck
}

// func to check login property
func loginCheck(columns []contract.Column, loginConfig *config.LoginConfig) []string {
	listMismatch := []string{}

	// check attempt at
	if attemptAt := isMatch(columns, loginConfig.AttemptAtProperty); attemptAt != "" {
		listMismatch = append(listMismatch, attemptAt)
	}

	// check credential
	if credential := isMatch(columns, loginConfig.CredentialProperty); credential != "" {
		listMismatch = append(listMismatch, credential)
	}

	// check deviceID
	if deviceID := isMatch(columns, loginConfig.DeviceIDProperty); deviceID != "" {
		listMismatch = append(listMismatch, deviceID)
	}

	// check FailedCounterProperty
	if FailedCounterProperty := isMatch(columns, loginConfig.FailedCounterProperty); FailedCounterProperty != "" {
		listMismatch = append(listMismatch, FailedCounterProperty)
	}

	// check LoginAtProperty
	if LoginAtProperty := isMatch(columns, loginConfig.LoginAtProperty); LoginAtProperty != "" {
		listMismatch = append(listMismatch, LoginAtProperty)
	}

	// check LoginAtProperty
	if LoginAtProperty := isMatch(columns, loginConfig.LoginAtProperty); LoginAtProperty != "" {
		listMismatch = append(listMismatch, LoginAtProperty)
	}

	// check TokenProperty
	if TokenProperty := isMatch(columns, loginConfig.TokenProperty); TokenProperty != "" {
		listMismatch = append(listMismatch, TokenProperty)
	}

	// check TypeProperty
	if TypeProperty := isMatch(columns, loginConfig.TypeProperty); TypeProperty != "" {
		listMismatch = append(listMismatch, TypeProperty)
	}

	return listMismatch
}

// func to check registration table property
func registrationCheck(columns []contract.Column, registrationConfig *config.RegistrationConfig) []string {
	listMismatch := []string{}

	// check CreatedAtProperty
	if CreatedAtProperty := isMatch(columns, registrationConfig.CreatedAtProperty); CreatedAtProperty != "" {
		listMismatch = append(listMismatch, CreatedAtProperty)
	}

	// check CredentialProperty
	if CredentialProperty := isMatch(columns, registrationConfig.CredentialProperty); CredentialProperty != "" {
		listMismatch = append(listMismatch, CredentialProperty)
	}

	// check DeviceIDProperty
	if DeviceIDProperty := isMatch(columns, registrationConfig.DeviceIDProperty); DeviceIDProperty != "" {
		listMismatch = append(listMismatch, DeviceIDProperty)
	}

	// check IDProperty
	if IDProperty := isMatch(columns, registrationConfig.IDProperty); IDProperty != "" {
		listMismatch = append(listMismatch, IDProperty)
	}

	// check OTPProperty
	if OTPProperty := isMatch(columns, registrationConfig.OTPProperty); OTPProperty != "" {
		listMismatch = append(listMismatch, OTPProperty)
	}

	// check RegistrationStatusProperty
	if RegistrationStatusProperty := isMatch(columns, registrationConfig.RegistrationStatusProperty); RegistrationStatusProperty != "" {
		listMismatch = append(listMismatch, RegistrationStatusProperty)
	}

	// check TokenProperty
	if TokenProperty := isMatch(columns, registrationConfig.TokenProperty); TokenProperty != "" {
		listMismatch = append(listMismatch, TokenProperty)
	}

	// check UserTypeProperty
	if UserTypeProperty := isMatch(columns, registrationConfig.UserTypeProperty); UserTypeProperty != "" {
		listMismatch = append(listMismatch, UserTypeProperty)
	}

	return listMismatch
}

// func to check reset password table property
func resetPasswordCheck(columns []contract.Column, resetPasswordConfig *config.ResetPasswordConfig) []string {
	listMismatch := []string{}

	// check CreatedAtProperty
	if CreatedAtProperty := isMatch(columns, resetPasswordConfig.CreatedAtProperty); CreatedAtProperty != "" {
		listMismatch = append(listMismatch, CreatedAtProperty)
	}

	// check CredentialProperty
	if CredentialProperty := isMatch(columns, resetPasswordConfig.CredentialProperty); CredentialProperty != "" {
		listMismatch = append(listMismatch, CredentialProperty)
	}

	// check IDProperty
	if IDProperty := isMatch(columns, resetPasswordConfig.IDProperty); IDProperty != "" {
		listMismatch = append(listMismatch, IDProperty)
	}

	// check OTPProperty
	if OTPProperty := isMatch(columns, resetPasswordConfig.OTPProperty); OTPProperty != "" {
		listMismatch = append(listMismatch, OTPProperty)
	}

	// check TokenProperty
	if TokenProperty := isMatch(columns, resetPasswordConfig.TokenProperty); TokenProperty != "" {
		listMismatch = append(listMismatch, TokenProperty)
	}

	// check UserTypeProperty
	if UserTypeProperty := isMatch(columns, resetPasswordConfig.UserTypeProperty); UserTypeProperty != "" {
		listMismatch = append(listMismatch, UserTypeProperty)
	}

	return listMismatch
}

// func to check user credential table property
func userCredentailCheck(columns []contract.Column, userConfig *config.User) []string {
	listMismatch := []string{}

	// check EmailProperty
	if EmailProperty := isMatch(columns, userConfig.EmailProperty); EmailProperty != "" {
		listMismatch = append(listMismatch, EmailProperty)
	}

	// check IDProperty
	if IDProperty := isMatch(columns, userConfig.IDProperty); IDProperty != "" {
		listMismatch = append(listMismatch, IDProperty)
	}

	// check PasswordProperty
	if PasswordProperty := isMatch(columns, userConfig.PasswordProperty); PasswordProperty != "" {
		listMismatch = append(listMismatch, PasswordProperty)
	}

	// check PhoneProperty
	if PhoneProperty := isMatch(columns, userConfig.PhoneProperty); PhoneProperty != "" {
		listMismatch = append(listMismatch, PhoneProperty)
	}

	// check PhotoProfileProperty
	if PhotoProfileProperty := isMatch(columns, userConfig.PhotoProfileProperty); PhotoProfileProperty != "" {
		listMismatch = append(listMismatch, PhotoProfileProperty)
	}

	// check UsernameProperty
	if UsernameProperty := isMatch(columns, userConfig.UsernameProperty); UsernameProperty != "" {
		listMismatch = append(listMismatch, UsernameProperty)
	}

	return listMismatch
}

// func to check user device table property
func userDeviceCheck(columns []contract.Column, userDeviceConfig *config.UserDeviceConfig) []string {
	listMismatch := []string{}

	// check DeviceIDProperty
	if DeviceIDProperty := isMatch(columns, userDeviceConfig.DeviceIDProperty); DeviceIDProperty != "" {
		listMismatch = append(listMismatch, DeviceIDProperty)
	}

	// check IDProperty
	if IDProperty := isMatch(columns, userDeviceConfig.IDProperty); IDProperty != "" {
		listMismatch = append(listMismatch, IDProperty)
	}

	// check UserIDProperty
	if UserIDProperty := isMatch(columns, userDeviceConfig.UserIDProperty); UserIDProperty != "" {
		listMismatch = append(listMismatch, UserIDProperty)
	}

	// check UserTypeProperty
	if UserTypeProperty := isMatch(columns, userDeviceConfig.UserTypeProperty); UserTypeProperty != "" {
		listMismatch = append(listMismatch, UserTypeProperty)
	}

	return listMismatch
}

// func to check user device table property
func userFCMCheck(columns []contract.Column, userFCMConfig *config.UserFCMTokenConfig) []string {
	listMismatch := []string{}

	// check IDProperty
	if IDProperty := isMatch(columns, userFCMConfig.IDProperty); IDProperty != "" {
		listMismatch = append(listMismatch, IDProperty)
	}

	// check TokenProperty
	if TokenProperty := isMatch(columns, userFCMConfig.TokenProperty); TokenProperty != "" {
		listMismatch = append(listMismatch, TokenProperty)
	}

	// check TimestampProperty
	if TimestampProperty := isMatch(columns, userFCMConfig.TimestampProperty); TimestampProperty != "" {
		listMismatch = append(listMismatch, TimestampProperty)
	}

	// check UserTypeProperty
	if UserTypeProperty := isMatch(columns, userFCMConfig.UserTypeProperty); UserTypeProperty != "" {
		listMismatch = append(listMismatch, UserTypeProperty)
	}

	// check UserIDProperty
	if UserIDProperty := isMatch(columns, userFCMConfig.UserIDProperty); UserIDProperty != "" {
		listMismatch = append(listMismatch, UserIDProperty)
	}

	return listMismatch
}

// check column from DB with property name defined on YAML
func isMatch(columns []contract.Column, propertyNameYAML string) string {
	for i := 0; i < len(columns); i++ {
		if columns[i].Field == propertyNameYAML {
			return ""
		}
	}

	return fmt.Sprintf("-mismatch/not defined property : %s", propertyNameYAML)
}

func TableStructureChecker(repository contract.TableStructureCheckerRepository) contract.TableStructureChecker {
	return &tableStructureCheckerImplementation{CheckerRepository: repository}
}
