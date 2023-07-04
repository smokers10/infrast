package usermanagement

import (
	"errors"
	"testing"
	"time"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	mockRepository        = contract.UserManagementRepositoryMock{Mock: mock.Mock{}}
	mockEncryption        = contract.EncryptionContractMock{Mock: mock.Mock{}}
	mockIdentifier        = contract.IdentfierContractMock{Mock: mock.Mock{}}
	mockJWT               = contract.JsonWebTokenContractMock{Mock: mock.Mock{}}
	mockMailer            = contract.MailerContractMock{Mock: mock.Mock{}}
	mockTemplateProcessor = contract.TemplateProcessorMock{Mock: mock.Mock{}}
	configuration         = config.Configuration{
		UserManagement: config.UserManagementConfig{
			UserCredential: []config.UserCredential{
				{
					Type:                 "Admin",
					UserTable:            "admins",
					Credential:           []string{"email", "username"},
					IDProperty:           "id",
					PhotoProfileProperty: "photo_profile",
					PasswordProperty:     "password",
				},
			},
			ResetPassword: config.ResetPasswordConfig{
				TableName:         "reset_password",
				TokenProperty:     "token",
				OTPProperty:       "otp",
				CreatedAtProperty: "created_at",
				ValidityDuration:  900,
				EmailTemplatePath: "template/reset-password.html",
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
			},
			Registration: config.RegistrationConfig{
				TableName:                  "registration",
				CredentialProperty:         "credential",
				TokenProperty:              "token",
				OTPProperty:                "otp",
				RegistrationStatusProperty: "status",
				EmailTemplatePath:          "templae/registration.html",
			},
		},
	}
)

func TestUserMatch(t *testing.T) {
	config := config.Configuration{
		UserManagement: config.UserManagementConfig{
			UserCredential: []config.UserCredential{
				{
					Type:                 "Admin",
					UserTable:            "admins",
					Credential:           []string{"email", "username"},
					IDProperty:           "id",
					PhotoProfileProperty: "photo_profile",
					PasswordProperty:     "password",
				},
			},
		},
	}

	t.Run("correct user type", func(t *testing.T) {
		_, err := UserManagement(&config, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
		assert.Empty(t, err)

		if err != nil {
			t.Fatal(err.Error())
		}
	})

	t.Run("incorrect user type", func(t *testing.T) {
		_, err := UserManagement(&config, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "User")
		assert.NotEmpty(t, err)
		if err != nil {
			t.Logf(err.Error())
		}
	})
}

func TestForgotPassword(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error make identifier", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error make OTP", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("test-token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error store forgot password", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("test-token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("ABC123").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user has email on its credentials (error template processing)", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "donatest@gmail.com",
			Email:        "dona@gmail.com",
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("test-token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("this-is-otp", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("ABC123").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user has email on its credentials (error sending email)", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "donatest@gmail.com",
			Email:        "dona@gmail.com",
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("test-token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("this-is-otp", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("ABC123").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("inteded error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user has phone numer on its credential", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "donatest",
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  "08112123255",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("test-token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("this-is-otp", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("ABC123").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success forgot password operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "donatest@gmail.com",
			Email:        "dona@gmail.com",
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("test-token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("this-is-otp", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("ABC123").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestLogin(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find user device", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error registering device", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error processing email template", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return(mock.Anything, errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error sending security concern email", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return(mock.Anything, nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find login session", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error create login session", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{}, nil).Once()
		mockRepository.Mock.On("CreateNewLoginSession", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update login session credential", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123"}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("failed attempt is more than allowed failed attempt", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 5, AttemptAt: time.Now().Unix() - 2500}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update login failed attempt", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 5, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find registration by credential", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration not verified", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "not verified"}, nil).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong password - error update failed attempt", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "verified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(false).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong password", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "verified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(false).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error signing token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "verified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("", errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success login operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: mock.Anything,
			UserID:   2,
			UserType: mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &configuration.UserManagement, mock.Anything).Return(&contract.LoginModel{ID: 1, Credential: "user123", FailedCounter: 1, AttemptAt: time.Now().Unix()}, nil).Once()
		mockRepository.Mock.On("UpdateLoginCredential", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, 0).Return(errors.New("intended error")).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "verified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockRepository.Mock.On("UpdateLoginFailedAttempt", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("asu", nil).Once()

		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "device-123")
		assert.NotEmpty(t, user)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestRegisterNewAccountWithEmail(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended errors")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user already exists", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate OTP", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate identifier", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error storing registration", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("secure-otp").Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error processing email template", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("secure-otp").Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("", errors.New("inteded error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error sending registration email", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("this-otp", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("secure-otp").Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("template", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success registration operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("as", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("iuah", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("secure-otp").Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestRegisterNewAccountWithUncertainCredential(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended errors")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user already exists", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			Password:     mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("uncertain credential input", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		token, status, err := userManagement.RegisterNewAccount("uncertain", mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})
}

func TestRegisterVerification(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find registration", func(t *testing.T) {
		mockRepository.Mock.On("FindOneRegistration", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, errors.New("intended error")).Once()

		status, err := userManagement.RegisterVerification("token", "otp")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneRegistration", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()

		status, err := userManagement.RegisterVerification("token", "otp")
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration is already verified", func(t *testing.T) {
		mockRepository.Mock.On("FindOneRegistration", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "verified"}, nil).Once()

		status, err := userManagement.RegisterVerification("token", "otp")
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong otp", func(t *testing.T) {
		mockRepository.Mock.On("FindOneRegistration", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "unverified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(false).Once()

		status, err := userManagement.RegisterVerification("token", "otp")
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update registration status", func(t *testing.T) {
		mockRepository.Mock.On("FindOneRegistration", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "unverified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockRepository.Mock.On("UpdateStatusRegistration", &configuration.UserManagement, mock.Anything).Return(errors.New("intended error")).Once()

		status, err := userManagement.RegisterVerification("token", "otp")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success registration verification", func(t *testing.T) {
		mockRepository.Mock.On("FindOneRegistration", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{RegistrationStatus: "unverified"}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockRepository.Mock.On("UpdateStatusRegistration", &configuration.UserManagement, mock.Anything).Return(nil).Once()

		status, err := userManagement.RegisterVerification("token", "otp")
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestRegistrationBioData(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}
	DynamicColVal := contract.DynamicColumnValue{
		Column: "(username, email, phone, address)",
		Value:  []string{"user123", "user@gmail.com", "08112123244", "Jl. TB Depan No.79B"},
	}

	t.Run("error find one user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user already exists", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{ID: 1}, nil).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find registration data", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, errors.New("intended errors")).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration data not exists", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error insert user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, DynamicColVal.Column, DynamicColVal.Value).Return(0, errors.New("intended error")).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find inserted user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, DynamicColVal.Column, DynamicColVal.Value).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("inserted user not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, DynamicColVal.Column, DynamicColVal.Value).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error insert user device", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, DynamicColVal.Column, DynamicColVal.Value).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error sign jwt token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, DynamicColVal.Column, DynamicColVal.Value).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("", errors.New("intended error")).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success registration bio data", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, DynamicColVal.Column, DynamicColVal.Value).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{ID: 1}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("jwt token", nil).Once()

		user, token, status, err := userManagement.RegistrationBioData("08112123244", &DynamicColVal)
		assert.NotEmpty(t, user)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestResetPassword(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find one forgot password", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{}, errors.New("intended error")).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("validity duration meet allowed limit - error delete session", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix() - 1000,
		}, nil).Once()
		mockRepository.Mock.On("DeleteForgotPassword", &configuration.UserManagement, mock.Anything).Return(errors.New("intended error")).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("validity duration meet allowed limit", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix() - 1000,
		}, nil).Once()
		mockRepository.Mock.On("DeleteForgotPassword", &configuration.UserManagement, mock.Anything).Return(nil).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong otp", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix(),
		}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(false).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong confirmation password input", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix(),
		}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password123")
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update user password", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix(),
		}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("new-safe-password").Once()
		mockRepository.Mock.On("UpdateUserPassword", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error delete forgot password session", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix(),
		}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("new-safe-password").Once()
		mockRepository.Mock.On("UpdateUserPassword", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("DeleteForgotPassword", &configuration.UserManagement, mock.Anything).Return(errors.New("intended error")).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success reset password operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneForgotPassword", &configuration.UserManagement, mock.Anything).Return(&contract.ForgotPasswordModel{
			ID:        1,
			CreatedAt: time.Now().Unix(),
		}, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("new-safe-password").Once()
		mockRepository.Mock.On("UpdateUserPassword", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("DeleteForgotPassword", &configuration.UserManagement, mock.Anything).Return(nil).Once()

		status, err := userManagement.ResetPassword("token", "otp", "password", "password")
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestLogout(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error delete login session", func(t *testing.T) {
		mockRepository.Mock.On("DeleteLoginSession", &configuration.UserManagement, mock.Anything).Return(errors.New("intended error")).Once()

		status, err := userManagement.Logout("device-id")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

	t.Run("success logout operatiion", func(t *testing.T) {
		mockRepository.Mock.On("DeleteLoginSession", &configuration.UserManagement, mock.Anything).Return(nil).Once()

		status, err := userManagement.Logout("device-id")
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}
