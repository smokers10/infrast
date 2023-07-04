package usermanagementrepository

import (
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/lib"
	"github.com/stretchr/testify/assert"
)

var (
	configuration = config.Configuration{
		UserManagement: config.UserManagementConfig{
			SelectedCredential: config.UserCredential{
				Type:                 "admin",
				UserTable:            "admins",
				Credential:           []string{"username", "email", "phone_numbers"},
				IDProperty:           "id",
				PhotoProfileProperty: "photo_profile",
				PasswordProperty:     "password",
				UsernameProperty:     "username",
				EmailProperty:        "email",
				PhoneProperty:        "phone",
			},
			ResetPassword: config.ResetPasswordConfig{
				TableName:          "reset_password",
				IDProperty:         "id",
				TokenProperty:      "token",
				OTPProperty:        "otp",
				CredentialProperty: "credential",
				CreatedAtProperty:  "created_at",
				ValidityDuration:   900,
				EmailTemplatePath:  "template/reset-password.html",
				UserTypeProperty:   "user_type",
			},
			Login: config.LoginConfig{
				TableName:             "login",
				TokenProperty:         "token",
				FailedCounterProperty: "failed_attempt",
				TypeProperty:          "user_type",
				CredentialProperty:    "credential",
				LoginAtProperty:       "loged_at",
				DeviceIDProperty:      "device_id",
				MaxFailedAttempt:      3,
				LoginBlockDuration:    300,
				AttemptAtProperty:     "attempted_at",
				EmailTemplatePath:     "template/security-concern.html",
			},
			Registration: config.RegistrationConfig{
				TableName:                  "registration",
				IDProperty:                 "id",
				CredentialProperty:         "credential",
				TokenProperty:              "token",
				OTPProperty:                "otp",
				RegistrationStatusProperty: "status",
				EmailTemplatePath:          "templae/registration.html",
				DeviceIDProperty:           "device_id",
				UserTypeProperty:           "user_type",
				CreatedAtProperty:          "created_at",
			},
			UserDevice: config.UserDeviceConfig{
				TableName:         "user_device",
				IDProperty:        "id",
				DeviceIDProperty:  "device_id",
				UserIDProperty:    "user_id",
				UserTypeProperty:  "yser_type",
				EmailTemplatePath: "template/security-concern.html",
			},
		},
	}
)

func TestCompleteLogin(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	query := fmt.Sprintf("UPDATE %s SET %s = \\$1, %s = \\$2 WHERE %s = \\$3", pq.QuoteIdentifier(configuration.UserManagement.Login.TableName),
		configuration.UserManagement.Login.TokenProperty, configuration.UserManagement.Login.LoginAtProperty, configuration.UserManagement.Login.DeviceIDProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err = repository.CompleteLoginSession(&configuration.UserManagement, "token", "device-id", time.Now().Unix())
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs("token", time.Now().Unix(), "device-id").WillReturnError(fmt.Errorf("error exec"))

		err = repository.CompleteLoginSession(&configuration.UserManagement, "token", "device-id", time.Now().Unix())
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs("token", time.Now().Unix(), "device-id").WillReturnResult(sqlmock.NewResult(1, 1))

		err = repository.CompleteLoginSession(&configuration.UserManagement, "token", "device-id", time.Now().Unix())
		assert.Empty(t, err)
	})
}

func TestCreateNewLogginSession(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	query := fmt.Sprintf("INSERT INTO %s (.+) VALUES (.+)", pq.QuoteIdentifier(umc.Login.TableName))
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.CreateNewLoginSession(&umc, "user@gmail.com", "device-id")
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.CreateNewLoginSession(&umc, "user@gmail.com", "device-id")
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(umc.SelectedCredential.Type, "user@gmail.com", "device-id").WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.CreateNewLoginSession(&umc, "user@gmail.com", "device-id")
		assert.Empty(t, err)
	})
}

func TestCreateNewUserDevice(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	userID := 1
	deviceID := "device-id"
	query := fmt.Sprintf("INSERT INTO %s (.+) VALUES (.+)", pq.QuoteIdentifier(umc.UserDevice.TableName))
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.CreateNewUserDevice(&umc, userID, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.CreateNewUserDevice(&umc, userID, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(deviceID, userID, umc.SelectedCredential.Type).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.CreateNewUserDevice(&umc, userID, deviceID)
		assert.Empty(t, err)
	})
}

func TestCreateRegistration(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	token := "token"
	credential := "credential"
	otp := "otp"
	device_id := "device_id"
	query := fmt.Sprintf("INSERT INTO %s (.+) VALUES (.+)", pq.QuoteIdentifier(umc.Registration.TableName))
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.CreateRegistration(&umc, token, credential, otp, device_id)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.CreateRegistration(&umc, token, credential, otp, device_id)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(umc.SelectedCredential.Type, token, credential, otp, device_id).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.CreateRegistration(&umc, token, credential, otp, device_id)
		assert.Empty(t, err)
	})
}

func TestDeleteForgotPassword(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	token := "token"
	query := fmt.Sprintf("DELETE FROM %v WHERE %s = \\$1 AND %s = \\$2", pq.QuoteIdentifier(umc.ResetPassword.TableName), umc.ResetPassword.TokenProperty, umc.ResetPassword.UserTypeProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.DeleteForgotPassword(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.DeleteForgotPassword(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(token, umc.ResetPassword.UserTypeProperty).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.DeleteForgotPassword(&umc, token)
		assert.Empty(t, err)
	})
}

func TestDeleteLoginSession(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	deviceID := "device-id"
	userType := umc.SelectedCredential.Type
	query := fmt.Sprintf("DELETE FROM %s WHERE %s = \\$1 AND %s = \\$2", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.DeviceIDProperty, umc.Login.TypeProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.DeleteLoginSession(&umc, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.DeleteLoginSession(&umc, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(deviceID, userType).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.DeleteLoginSession(&umc, deviceID)
		assert.Empty(t, err)
	})
}

func TestFindOneForgotPassword(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	token := "token"
	userType := umc.SelectedCredential.Type
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as otp, %s as credential, %s as created_at FROM %s WHERE %s = \\$1 AND %s = \\$2 LIMIT 1", umc.ResetPassword.IDProperty, umc.ResetPassword.TokenProperty,
		umc.ResetPassword.OTPProperty, umc.ResetPassword.CredentialProperty, umc.ResetPassword.CreatedAtProperty, pq.QuoteIdentifier(umc.ResetPassword.TableName), umc.ResetPassword.TokenProperty, umc.ResetPassword.UserTypeProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.FindOneForgotPassword(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.FindOneForgotPassword(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		curentTime := time.Now().Unix()
		expectedRow := sqlmock.NewRows([]string{"id", "token", "otp", "credential", "created_at"}).AddRow(1, "12asd-a34s-421ff-123", "ABD1234", "user1@gmail.com", curentTime)

		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(token, userType).WillReturnRows(expectedRow)

		fp, err := repository.FindOneForgotPassword(&umc, token)
		assert.Empty(t, err)

		t.Run("check reset password data : ", func(t *testing.T) {
			assert.NotEmpty(t, fp.CreatedAt)
			assert.NotEmpty(t, fp.Credential)
			assert.NotEmpty(t, fp.ID)
			assert.NotEmpty(t, fp.OTP)
			assert.NotEmpty(t, fp.Token)
			assert.NotEmpty(t, fp.Type)
			t.Logf("data : %v", fp)
		})
	})
}

func TestFindoneLoginSession(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	deviceID := "device_id"
	userType := umc.SelectedCredential.Type
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as credential, %s as type, %s as login_at, %s as attempt_at, %s as failed_counter FROM %s WHERE %s = \\$1 AND %s = \\$2 LIMIT 1",
		umc.Login.DeviceIDProperty, umc.Login.TokenProperty, umc.Login.CredentialProperty, umc.Login.TypeProperty, umc.Login.LoginAtProperty, umc.Login.AttemptAtProperty,
		umc.Login.FailedCounterProperty, pq.QuoteIdentifier(umc.Login.TableName), umc.Login.DeviceIDProperty, umc.Login.TypeProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.FindOneLoginSession(&umc, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(deviceID, userType).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.FindOneLoginSession(&umc, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		expectedRows := sqlmock.NewRows([]string{"id", "token", "credential", "type", "login_at", "attempt_at", "failed_counter"}).AddRow(1, "$asd123d!.", "user@gmail.com", userType, time.Now().Unix(), time.Now().Unix(), 3)
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(deviceID, userType).WillReturnRows(expectedRows)

		loginSession, err := repository.FindOneLoginSession(&umc, deviceID)
		assert.Empty(t, err)
		t.Run("check reset password data : ", func(t *testing.T) {
			assert.NotEmpty(t, loginSession.AttemptAt)
			assert.NotEmpty(t, loginSession.Credential)
			assert.NotEmpty(t, loginSession.DeviceID)
			assert.NotEmpty(t, loginSession.FailedCounter)
			assert.NotEmpty(t, loginSession.ID)
			assert.NotEmpty(t, loginSession.LoginAt)
			assert.NotEmpty(t, loginSession.Token)
			assert.NotEmpty(t, loginSession.Type)
			t.Logf("data : %v", loginSession)
		})
	})
}

func TestFindOneRegistration(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	token := "token"
	userType := umc.SelectedCredential.Type
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as otp, %s as credential, %s as created_at, %s as type, %s as registration_status, %s as device_id FROM %s WHERE %s = \\$1 AND %s = \\$2 LIMIT 1",
		umc.Registration.IDProperty, umc.Registration.TokenProperty, umc.Registration.OTPProperty, umc.Registration.CredentialProperty, umc.Registration.CreatedAtProperty,
		umc.Registration.UserTypeProperty, umc.Registration.RegistrationStatusProperty, umc.Registration.DeviceIDProperty,
		pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.TokenProperty, umc.Registration.UserTypeProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.FindOneRegistration(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(token, userType).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.FindOneRegistration(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		expectedRows := sqlmock.NewRows([]string{"id", "token", "otp", "credential", "created_at", "type", "registration_status", "device_id"}).
			AddRow(1, "token", "otp", "user@gmail.com", time.Now().Unix(), userType, "unverified", "device-id")
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(token, userType).WillReturnRows(expectedRows)

		registration, err := repository.FindOneRegistration(&umc, token)
		assert.Empty(t, err)

		t.Run("check registration data", func(t *testing.T) {
			assert.NotEmpty(t, registration.CreatedAt)
			assert.NotEmpty(t, registration.Credential)
			assert.NotEmpty(t, registration.DeviceID)
			assert.NotEmpty(t, registration.ID)
			assert.NotEmpty(t, registration.OTP)
			assert.NotEmpty(t, registration.RegistrationStatus)
			assert.NotEmpty(t, registration.Token)
			assert.NotEmpty(t, registration.Type)

			t.Logf("registration data : %v", registration)
		})
	})
}

func TestFindOneRegistrationByCredential(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	credential := "user@gmail.com"
	userType := umc.SelectedCredential.Type
	query := fmt.Sprintf("SELECT %s as id, %s as token, %s as otp, %s as credential, %s as created_at, %s as type, %s as registration_status, %s as device_id FROM %s WHERE %s = \\$1 AND %s = \\$2 LIMIT 1",
		umc.Registration.IDProperty, umc.Registration.TokenProperty, umc.Registration.OTPProperty, umc.Registration.CredentialProperty, umc.Registration.CreatedAtProperty,
		umc.Registration.UserTypeProperty, umc.Registration.RegistrationStatusProperty, umc.Registration.DeviceIDProperty,
		pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.CredentialProperty, umc.Registration.UserTypeProperty)
	t.Logf("query on test : %v", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.FindOneRegistrationByCredential(&umc, credential)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(credential, userType).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.FindOneRegistrationByCredential(&umc, credential)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		expectedRows := sqlmock.NewRows([]string{"id", "token", "otp", "credential", "created_at", "type", "registration_status", "device_id"}).
			AddRow(1, "token", "otp", credential, time.Now().Unix(), userType, "unverified", "device-id")
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(credential, userType).WillReturnRows(expectedRows)

		registration, err := repository.FindOneRegistrationByCredential(&umc, credential)
		assert.Empty(t, err)

		t.Run("check registration data", func(t *testing.T) {
			assert.NotEmpty(t, registration.CreatedAt)
			assert.NotEmpty(t, registration.Credential)
			assert.NotEmpty(t, registration.DeviceID)
			assert.NotEmpty(t, registration.ID)
			assert.NotEmpty(t, registration.OTP)
			assert.NotEmpty(t, registration.RegistrationStatus)
			assert.NotEmpty(t, registration.Token)
			assert.NotEmpty(t, registration.Type)

			t.Logf("registration data : %v", registration)
		})
	})
}

func TestFindOneUser(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	credential := "user@gmail.com"
	selectedCred := umc.SelectedCredential
	tableName := selectedCred.UserTable
	_, whereClause := lib.UserQueryMakerTesting(selectedCred.Credential)
	query := fmt.Sprintf("SELECT DISTINCT %s as id, %s as email, %s as phone , %s as photo_profile, %s as password FROM %s WHERE %s LIMIT 1", selectedCred.IDProperty,
		selectedCred.EmailProperty, selectedCred.PhoneProperty, selectedCred.PhotoProfileProperty, selectedCred.PasswordProperty, pq.QuoteIdentifier(tableName), whereClause)

	t.Logf("query to test : %s", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.FindOneUser(&umc, credential)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(credential).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.FindOneUser(&umc, credential)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("user not find", func(t *testing.T) {
		expectedRows := sqlmock.NewRows([]string{selectedCred.IDProperty, selectedCred.EmailProperty, selectedCred.UsernameProperty, selectedCred.PhoneProperty,
			selectedCred.PhotoProfileProperty, selectedCred.PasswordProperty})
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(credential).WillReturnRows(expectedRows)

		user, err := repository.FindOneUser(&umc, credential)
		assert.Empty(t, err)
		t.Log(user)
	})

	t.Run("success operation", func(t *testing.T) {
		expectedRows := sqlmock.NewRows([]string{selectedCred.IDProperty, selectedCred.EmailProperty, selectedCred.UsernameProperty, selectedCred.PhoneProperty,
			selectedCred.PhotoProfileProperty, selectedCred.PasswordProperty}).
			AddRow(1, "user@gmail.com", "JohnDoe", "1234567890", "photo.png", "password")
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(credential).WillReturnRows(expectedRows)

		user, err := repository.FindOneUser(&umc, credential)
		assert.Empty(t, err)

		t.Run("check user data", func(t *testing.T) {
			assert.NotEmpty(t, user.ID)
			assert.NotEmpty(t, user.Email)
			assert.NotEmpty(t, user.Username)
			assert.NotEmpty(t, user.PhoneNumber)
			assert.NotEmpty(t, user.PhotoProfile)
			assert.NotEmpty(t, user.Password)

			t.Logf("user data: %v", user)
		})
	})
}

func TestFindUserDevice(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	userID := 1
	deviceID := "device-123"

	query := fmt.Sprintf("SELECT %s as id, %s as device_id, %s as user_id, %s as user_type FROM %s WHERE %s = \\$1 AND %s = \\$2 LIMIT 1", umc.UserDevice.IDProperty,
		umc.UserDevice.DeviceIDProperty, umc.UserDevice.UserIDProperty, umc.UserDevice.UserTypeProperty, pq.QuoteIdentifier(umc.UserDevice.TableName),
		umc.UserDevice.UserIDProperty, umc.UserDevice.DeviceIDProperty)
	t.Logf("query to test : %s", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.FindUserDevice(&umc, userID, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on query", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(userID, deviceID).WillReturnError(fmt.Errorf("error query"))

		_, err := repository.FindUserDevice(&umc, userID, deviceID)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		expectedRows := sqlmock.NewRows([]string{"id", "device_id", "user_id", "user_type"}).
			AddRow(1, deviceID, userID, "user")

		mock.ExpectPrepare(query)
		mock.ExpectQuery(query).WithArgs(userID, deviceID).WillReturnRows(expectedRows)

		result, err := repository.FindUserDevice(&umc, userID, deviceID)
		assert.Empty(t, err)

		t.Run("check user device data", func(t *testing.T) {
			assert.Equal(t, userID, result.UserID)
			assert.Equal(t, deviceID, result.DeviceID)
			assert.Equal(t, "user", result.UserType)

			t.Logf("user device data: %v", result)
		})
	})
}

func TestStoreForgotPassword(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	credential := "user@gmail.com"
	token := "token123"
	otp := "123456"

	query := fmt.Sprintf("INSERT INTO %s (.+) VALUES (.+)", pq.QuoteIdentifier(umc.ResetPassword.TableName))

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.StoreForgotPassword(&umc, credential, token, otp)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on execute", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(credential, token, otp, umc.SelectedCredential.Type, time.Now().Unix()).WillReturnError(fmt.Errorf("error execute"))

		err := repository.StoreForgotPassword(&umc, credential, token, otp)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WithArgs(credential, token, otp, umc.SelectedCredential.Type, time.Now().Unix()).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.StoreForgotPassword(&umc, credential, token, otp)
		assert.Empty(t, err)
	})
}

func TestStoreUser(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	column := "(email, username, password)"
	args := []string{"user@example.com", "user123", "password123"}

	query := fmt.Sprintf("INSERT INTO %s (.+) VALUES (.+)", pq.QuoteIdentifier(umc.SelectedCredential.UserTable))

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		_, err := repository.StoreUser(&umc, column, args...)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		_, err := repository.StoreUser(&umc, column, args...)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnResult(sqlmock.NewResult(1, 1))

		insertedID, err := repository.StoreUser(&umc, column, args...)
		assert.Empty(t, err)
		assert.Equal(t, 1, insertedID)

		t.Logf("inserted ID: %v", insertedID)
	})
}

func TestUpdateLoginCredential(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	deviceID := "device-id"
	credential := "new-credential"

	query := fmt.Sprintf("UPDATE %s SET %s = \\$1 WHERE %s = \\$2", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.CredentialProperty, umc.Login.DeviceIDProperty)
	t.Logf("query to test : %s", query)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.UpdateLoginCredential(&umc, deviceID, credential)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.UpdateLoginCredential(&umc, deviceID, credential)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.UpdateLoginCredential(&umc, deviceID, credential)
		assert.Empty(t, err)

		t.Logf("credential updated successfully")
	})
}

func TestUpdateLoginFailedAttempt(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	deviceID := "device-id"
	newNumber := 5

	query := fmt.Sprintf("UPDATE %s SET %s = \\$1 WHERE %s = \\$2", pq.QuoteIdentifier(umc.Login.TableName), umc.Login.FailedCounterProperty, umc.Login.DeviceIDProperty)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.UpdateLoginFailedAttempt(&umc, deviceID, newNumber)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.UpdateLoginFailedAttempt(&umc, deviceID, newNumber)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.UpdateLoginFailedAttempt(&umc, deviceID, newNumber)
		assert.Empty(t, err)

		t.Logf("failed attempt updated successfully")
	})
}

func TestUpdateStatusRegistration(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	token := "registration-token"

	query := fmt.Sprintf("UPDATE %s SET %s = \\$1 WHERE %s = \\$2", pq.QuoteIdentifier(umc.Registration.TableName), umc.Registration.RegistrationStatusProperty, umc.Registration.TokenProperty)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.UpdateStatusRegistration(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.UpdateStatusRegistration(&umc, token)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.UpdateStatusRegistration(&umc, token)
		assert.Empty(t, err)

		t.Logf("registration status updated successfully")
	})
}

func TestUpdateUserPassword(t *testing.T) {
	umc := configuration.UserManagement
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repository := UserManagementRepository(db)
	credential := "example@domain.com"
	safePassword := "safepassword"

	tableName := umc.SelectedCredential.UserTable
	credentials := umc.SelectedCredential.Credential
	whereClause := lib.WhereClause(credentials, "\\$2")

	query := fmt.Sprintf("UPDATE %s SET %s = \\$1 WHERE %s", pq.QuoteIdentifier(tableName), umc.SelectedCredential.PasswordProperty, whereClause)

	t.Run("error on prepare", func(t *testing.T) {
		mock.ExpectPrepare(query).WillReturnError(fmt.Errorf("error prepare"))

		err := repository.UpdateUserPassword(&umc, credential, safePassword)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("error on exec", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnError(fmt.Errorf("error exec"))

		err := repository.UpdateUserPassword(&umc, credential, safePassword)
		assert.NotEmpty(t, err)
		t.Logf("error: %v", err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mock.ExpectPrepare(query)
		mock.ExpectExec(query).WillReturnResult(sqlmock.NewResult(1, 1))

		err := repository.UpdateUserPassword(&umc, credential, safePassword)
		assert.Empty(t, err)

		t.Logf("user password updated successfully")
	})
}
