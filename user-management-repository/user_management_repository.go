package usermanagementrepository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/smokers10/infrast/lib"
)

type userManagementRepositoryImplementation struct {
	db *sql.DB
}

// CompleteLoginSession implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) CompleteLoginSession(umc *config.UserManagementConfig, token string, device_id string, login_at int64) error {
	// UPDATE <table name> SET token = $1, loged_at = $2 WHERE device_id = %3
	query := fmt.Sprintf("UPDATE %s SET %s = $1, %s = $2 WHERE %s = $3", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.TokenProperty, umc.Login.LoginAtProperty, umc.Login.DeviceIDProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(token, login_at, device_id); err != nil {
		return err
	}

	return nil
}

// CreateNewLoginSession implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) CreateNewLoginSession(umc *config.UserManagementConfig, credential string, device_id string) error {
	// insert into -login- (type, credential, device_id) VALUES ($1..$n)
	query := fmt.Sprintf("INSERT INTO %s (%s, %s, %s) VALUES ($1, $2, $3)", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.TypeProperty, umc.Login.CredentialProperty, umc.Login.DeviceIDProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(umc.SelectedCredential.Type, credential, device_id); err != nil {
		return err
	}

	return nil
}

// CreateNewUserDevice implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) CreateNewUserDevice(umc *config.UserManagementConfig, user_id int, device_id string) error {
	// insert info -user device- (device_id, user_id, user_type) VALUES ($1..$n)
	query := fmt.Sprintf("INSERT INTO %s (%s, %s, %s) VALUES ($1, $2, $3)", pq.QuoteIdentifier(umc.UserDevice.TableName), umc.UserDevice.DeviceIDProperty, umc.UserDevice.UserIDProperty, umc.UserDevice.UserTypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(device_id, user_id, umc.SelectedCredential.Type); err != nil {
		return err
	}

	return nil
}

// CreateRegistration implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) CreateRegistration(umc *config.UserManagementConfig, token string, credential string, otp string, device_id string) error {
	// insert into -registration- (type, token, credential, otp, device_id) VALUES ($1..n)
	query := fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s, %s) VALUES ($1, $2, $3, $4, $5)", pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.UserTypeProperty, umc.Registration.TokenProperty,
		umc.Registration.CredentialProperty, umc.Registration.OTPProperty, umc.Registration.DeviceIDProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(umc.SelectedCredential.Type, token, credential, otp, device_id); err != nil {
		return err
	}

	return nil
}

// DeleteForgotPassword implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) DeleteForgotPassword(umc *config.UserManagementConfig, token string) error {
	// DELETE FROM -forgot_password- WHERE token = $1 AND user_type = $2
	query := fmt.Sprintf("DELETE FROM %v WHERE %s = $1 AND %s = $2", pq.QuoteIdentifier(umc.ResetPassword.TableName), umc.ResetPassword.TokenProperty, umc.ResetPassword.UserTypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(token, umc.ResetPassword.UserTypeProperty); err != nil {
		return err
	}

	return nil
}

// DeleteLoginSession implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) DeleteLoginSession(umc *config.UserManagementConfig, device_id string) error {
	// DELETE FROM -login- WHERE device_id = $1 AND user_type = $1
	query := fmt.Sprintf("DELETE FROM %s WHERE %s = $1 AND %s = $2", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.DeviceIDProperty, umc.Login.TypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(device_id, umc.SelectedCredential.Type); err != nil {
		return err
	}

	return nil
}

// FindOneForgotPassword implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) FindOneForgotPassword(umc *config.UserManagementConfig, token string) (*contract.ForgotPasswordModel, error) {
	result := contract.ForgotPasswordModel{}
	// SELECT id, token, otp, credential, created_at FROM <table name> WHERE token = $1 AND user_type = $2 LIMIT 1
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as otp, %s as credential, %s as created_at FROM %s WHERE %s = $1 AND %s = $2 LIMIT 1", umc.ResetPassword.IDProperty, umc.ResetPassword.TokenProperty,
		umc.ResetPassword.OTPProperty, umc.ResetPassword.CredentialProperty, umc.ResetPassword.CreatedAtProperty, pq.QuoteIdentifier(umc.ResetPassword.TableName), umc.ResetPassword.TokenProperty, umc.ResetPassword.UserTypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	if err := stmt.QueryRow(token, umc.SelectedCredential.Type).Scan(&result.ID, &result.Token, &result.OTP, &result.Credential, &result.CreatedAt); err != nil {
		return nil, err
	}

	result.Type = umc.SelectedCredential.Type

	return &result, nil
}

// FindOneLoginSession implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) FindOneLoginSession(umc *config.UserManagementConfig, device_id string) (*contract.LoginModel, error) {
	result := contract.LoginModel{}
	// SELECT id, token, credential, type, logged_at, attempted_at, failed_attempt FROM <table name> WHERE device_id = $1 AND user_type = $2
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as credential, %s as type, %s as login_at, %s as attempt_at, %s as failed_counter FROM %s WHERE %s = $1 AND %s = $2 LIMIT 1",
		umc.Login.DeviceIDProperty, umc.Login.TokenProperty, umc.Login.CredentialProperty, umc.Login.TypeProperty, umc.Login.LoginAtProperty, umc.Login.AttemptAtProperty,
		umc.Login.FailedCounterProperty, pq.QuoteIdentifier(umc.Login.TableName), umc.Login.DeviceIDProperty, umc.Login.TypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	if err := stmt.QueryRow(device_id, umc.SelectedCredential.Type).Scan(&result.ID, &result.Token, &result.Credential, &result.Type, &result.LoginAt, &result.AttemptAt, &result.FailedCounter); err != nil {
		return nil, err
	}

	result.DeviceID = device_id

	return &result, nil
}

// FindOneRegistration implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) FindOneRegistration(umc *config.UserManagementConfig, token string) (*contract.RegistrationModel, error) {
	result := contract.RegistrationModel{}
	// SELECT id, token, otp, credential, created_at, type, registration_status, device_id FROM regigstration WHERE token = $1 AND user_Type $2
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as otp, %s as credential, %s as created_at, %s as type, %s as registration_status, %s as device_id FROM %s WHERE %s = $1 AND %s = $2 LIMIT 1",
		umc.Registration.IDProperty, umc.Registration.TokenProperty, umc.Registration.OTPProperty, umc.Registration.CredentialProperty, umc.Registration.CreatedAtProperty,
		umc.Registration.UserTypeProperty, umc.Registration.RegistrationStatusProperty, umc.Registration.DeviceIDProperty,
		pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.TokenProperty, umc.Registration.UserTypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	if err := stmt.QueryRow(token, umc.SelectedCredential.Type).Scan(&result.ID, &result.Token, &result.OTP, &result.Credential, &result.CreatedAt, &result.Type, &result.RegistrationStatus, &result.DeviceID); err != nil {
		return nil, err
	}

	return &result, nil
}

// FindOneRegistrationByCredential implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) FindOneRegistrationByCredential(umc *config.UserManagementConfig, credential string) (*contract.RegistrationModel, error) {
	result := contract.RegistrationModel{}
	// SELECT id, token, otp, credential, created_at, type, registration_status, device_id FROM regigstration WHERE token = $1 AND user_type = $2
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as otp, %s as credential, %s as created_at, %s as type, %s as registration_status, %s as device_id FROM %s WHERE %s = $1 AND %s = $2 LIMIT 1",
		umc.Registration.IDProperty, umc.Registration.TokenProperty, umc.Registration.OTPProperty, umc.Registration.CredentialProperty, umc.Registration.CreatedAtProperty,
		umc.Registration.UserTypeProperty, umc.Registration.RegistrationStatusProperty, umc.Registration.DeviceIDProperty,
		pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.CredentialProperty, umc.Registration.UserTypeProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	if err := stmt.QueryRow(credential, umc.SelectedCredential.Type).Scan(&result.ID, &result.Token, &result.OTP, &result.Credential, &result.CreatedAt, &result.Type, &result.RegistrationStatus, &result.DeviceID); err != nil {
		return nil, err
	}

	return &result, nil
}

// FindOneUser implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) FindOneUser(umc *config.UserManagementConfig, credential string) (*contract.UserModel, error) {
	result := contract.UserModel{}
	selectedCred := umc.SelectedCredential
	tableName := selectedCred.UserTable
	credentials := selectedCred.Credential
	_, whereClause := lib.UserQueryMaker(credentials)

	// SELECT DISTINCT id, email, username, phone, photo_profile, password FROM <table name> WHERE *credential = $1 OR ... n*
	query := fmt.Sprintf("SELECT DISTINCT %s as id, %s as email, %s as phone , %s as photo_profile, %s as password, %s FROM %s WHERE %s LIMIT 1", selectedCred.IDProperty, selectedCred.EmailProperty, selectedCred.UsernameProperty, selectedCred.PhoneProperty,
		selectedCred.PhotoProfileProperty, selectedCred.PasswordProperty, pq.QuoteIdentifier(tableName), whereClause)

	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	if err := stmt.QueryRow(credential).Scan(&result.ID, &result.Email, &result.Username, &result.PhoneNumber, &result.PhotoProfile, &result.Password); err != nil {
		return nil, err
	}

	return &result, nil
}

// FindUserDevice implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) FindUserDevice(umc *config.UserManagementConfig, user_id int, device_id string) (*contract.UserDeviceModel, error) {
	result := contract.UserDeviceModel{}

	// SELECT id, device_id, user_id, user_type FROM <table name> WHERE user_id = $1 AND device_id = $2
	query := fmt.Sprintf("SELECT %s as id, %s as device_id, %s as user_id, %s as user_type FROM %s WHERE %s = $1 AND %s = $2 LIMIT 1", umc.UserDevice.IDProperty,
		umc.UserDevice.DeviceIDProperty, umc.UserDevice.UserIDProperty, umc.UserDevice.UserTypeProperty, pq.QuoteIdentifier(umc.UserDevice.TableName),
		umc.UserDevice.UserIDProperty, umc.UserDevice.DeviceIDProperty)

	stmt, err := i.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	defer stmt.Close()

	if err := stmt.QueryRow(user_id, device_id).Scan(&result.ID, &result.DeviceID, &result.UserID, &result.UserType); err != nil {
		return nil, err
	}

	return &result, nil
}

// StoreForgotPassword implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) StoreForgotPassword(umc *config.UserManagementConfig, credential string, token string, otp string) error {
	// INSERT INTO <table name> (credential, token, otp, type, created_at) VALUES ($1..n)
	query := fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s, %s) VALUES ($1, $2, $3, $4, $5)", pq.QuoteIdentifier(umc.ResetPassword.TableName), umc.ResetPassword.CredentialProperty,
		umc.ResetPassword.TokenProperty, umc.ResetPassword.OTPProperty, umc.ResetPassword.UserTypeProperty, umc.ResetPassword.CreatedAtProperty)

	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(credential, token, otp, umc.SelectedCredential.Type, time.Now().Unix()); err != nil {
		return err
	}

	return nil
}

// StoreUser implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) StoreUser(umc *config.UserManagementConfig, column string, args ...string) (int, error) {
	value := lib.InsertQueryValueMaker(args...)
	// INSERT INTO <table name> <column> VALUES <values>
	query := fmt.Sprintf("INSERT INTO %s %s VALUES %s", pq.QuoteIdentifier(umc.SelectedCredential.UserTable), column, value)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	result, err := stmt.Exec()
	if err != nil {
		return 0, err
	}

	insertedID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	return int(insertedID), nil
}

// UpdateLoginCredential implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) UpdateLoginCredential(umc *config.UserManagementConfig, device_id string, credential string) error {
	// UPDATE <table name> SET credential = $1 WHERE device_id = $1
	query := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s = $2", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.CredentialProperty, umc.Login.DeviceIDProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(credential, device_id); err != nil {
		return err
	}

	return nil
}

// UpdateLoginFailedAttempt implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) UpdateLoginFailedAttempt(umc *config.UserManagementConfig, device_id string, new_number int) error {
	// UPDATE <table name> SET failed_attempt = $1 WHERE device_id = $2
	query := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s = $2", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.FailedCounterProperty, umc.Login.DeviceIDProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(new_number, device_id); err != nil {
		return err
	}

	return nil
}

// UpdateStatusRegistration implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) UpdateStatusRegistration(umc *config.UserManagementConfig, token string) error {
	// UPDATE <table name> SET registration_status = $1 WHERE token = $2
	query := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s = $2", pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.RegistrationStatusProperty, umc.Registration.TokenProperty)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec("verified", token); err != nil {
		return err
	}

	return nil
}

// UpdateUserPassword implements contract.UserManagementRepository.
func (i *userManagementRepositoryImplementation) UpdateUserPassword(umc *config.UserManagementConfig, credential string, safe_password string) error {
	tableName := umc.SelectedCredential.UserTable
	credentials := umc.SelectedCredential.Credential
	whereClause := lib.WhereClause(credentials, "$2")

	// UPDATE <table name> SET password = $1 WHERE (credential = $1 OR ...n)
	query := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s", pq.QuoteIdentifier(tableName), umc.SelectedCredential.PasswordProperty, whereClause)
	stmt, err := i.db.Prepare(query)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(safe_password, credential); err != nil {
		return err
	}

	return nil
}

func UserManagementRepository(db *sql.DB) contract.UserManagementRepository {
	return &userManagementRepositoryImplementation{db: db}
}
