package usermanagement

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/smokers10/infrast/config"
	"github.com/smokers10/infrast/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	errFoo                = errors.New("intended error")
	mockRepository        = contract.UserManagementRepositoryMock{Mock: mock.Mock{}}
	mockEncryption        = contract.EncryptionContractMock{Mock: mock.Mock{}}
	mockIdentifier        = contract.IdentfierContractMock{Mock: mock.Mock{}}
	mockJWT               = contract.JsonWebTokenContractMock{Mock: mock.Mock{}}
	mockMailer            = contract.MailerContractMock{Mock: mock.Mock{}}
	mockWhatsapp          = contract.WhatsappMock{Mock: mock.Mock{}}
	mockTemplateProcessor = contract.TemplateProcessorMock{Mock: mock.Mock{}}
	configuration         = config.Configuration{
		UserManagement: config.UserManagementConfig{
			MessageTemplate: config.MessageTemplate{
				NewRegistrationEmailTemplatePath:  "template/new-reg-email.html",
				NewDeviceWarningEmailTemplatePath: "template/new-device-email.html",
				ForgotPasswordEmailTemplatePath:   "template/forgot-password-email.html",
				NewRegistrationMessageTemplate:    "your registration otp is %v",
				NewDeviceWarningMessageTemplate:   "you logged at another device klick link bellow to logout\n\n%v",
				ForgotPasswordMessageTemplate:     "your reset password opt is %v",
			},
			UserCredential: []config.UserCredential{
				{
					Type:                 "Admin",
					UserTable:            "admins",
					Credential:           []string{"email", "username"},
					IDProperty:           "id",
					PhotoProfileProperty: "photo_profile",
					PasswordProperty:     "password",
					UsernameProperty:     "username",
					EmailProperty:        "email",
					PhoneProperty:        "phone",
				},
			},
			ResetPassword: config.ResetPasswordConfig{
				TableName:         "reset_password",
				TokenProperty:     "token",
				OTPProperty:       "otp",
				CreatedAtProperty: "created_at",
				ValidityDuration:  900,
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
			},
		},
	}
)

func TestUpsertUserFCMToken(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}
	umc := &configuration.UserManagement
	fcmModel := &contract.UserFCMTokenModel{
		ID:        1,
		Token:     mock.Anything,
		Timestamp: time.Now().Unix(),
		UserType:  mock.Anything,
		UserID:    mock.Anything,
	}

	t.Run("incomplete required data", func(t *testing.T) {
		status, err := userManagement.UpsertUserFCMToken("", 1)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error get FCM token", func(t *testing.T) {
		mockRepository.Mock.On("GetFCMToken", umc, mock.Anything).Return(&contract.UserFCMTokenModel{}, errFoo).Once()

		status, err := userManagement.UpsertUserFCMToken("token", 1)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("FCM not exists - error store FCM token", func(t *testing.T) {
		mockRepository.Mock.On("GetFCMToken", umc, mock.Anything).Return(&contract.UserFCMTokenModel{}, nil).Once()
		mockRepository.Mock.On("StoreFCMToken", umc, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		status, err := userManagement.UpsertUserFCMToken("token", 1)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("FCM not exists - success store FCM token", func(t *testing.T) {
		mockRepository.Mock.On("GetFCMToken", umc, mock.Anything).Return(&contract.UserFCMTokenModel{}, nil).Once()
		mockRepository.Mock.On("StoreFCMToken", umc, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		status, err := userManagement.UpsertUserFCMToken("token", 1)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})

	t.Run("FCM exists - error update FCM token", func(t *testing.T) {
		mockRepository.Mock.On("GetFCMToken", umc, mock.Anything).Return(fcmModel, nil).Once()
		mockRepository.Mock.On("UpdateFCMToken", umc, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		status, err := userManagement.UpsertUserFCMToken("token", 1)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("FCM exists - success update FCM token", func(t *testing.T) {
		mockRepository.Mock.On("GetFCMToken", umc, mock.Anything).Return(fcmModel, nil).Once()
		mockRepository.Mock.On("UpdateFCMToken", umc, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		status, err := userManagement.UpsertUserFCMToken("token", 1)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestCheckUserJWTToken(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	umc := &configuration.UserManagement
	loginModel := &contract.LoginModel{
		ID:            1,
		Token:         mock.Anything,
		Credential:    mock.Anything,
		Type:          mock.Anything,
		DeviceID:      mock.Anything,
		LoginAt:       time.Now().Unix(),
		AttemptAt:     time.Now().Unix(),
		FailedCounter: 2,
	}

	t.Run("incomplete required data", func(t *testing.T) {
		checkResult, status, err := userManagement.CheckUserJWTToken("")
		assert.Empty(t, checkResult)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find one login session", func(t *testing.T) {
		mockRepository.Mock.On("FindOneLoginSession", umc, mock.Anything).Return(&contract.LoginModel{}, errFoo).Once()

		checkResult, status, err := userManagement.CheckUserJWTToken("device-id-123")
		assert.Empty(t, checkResult)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("login session not exist", func(t *testing.T) {
		mockRepository.Mock.On("FindOneLoginSession", umc, mock.Anything).Return(&contract.LoginModel{}, nil).Once()

		checkResult, status, err := userManagement.CheckUserJWTToken("device-id-123")
		assert.Empty(t, checkResult)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error parse jwt token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneLoginSession", umc, mock.Anything).Return(loginModel, nil).Once()
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(map[string]interface{}{}, errFoo).Once()

		checkResult, status, err := userManagement.CheckUserJWTToken("device-id-123")
		assert.Empty(t, checkResult)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("expired token", func(t *testing.T) {
		payload := map[string]interface{}{
			"sub":  1,
			"type": mock.Anything,
			"iat":  time.Now().UTC().Unix(),
			"eat":  time.Now().UTC().AddDate(0, 0, -2).Unix(),
		}

		mockRepository.Mock.On("FindOneLoginSession", umc, mock.Anything).Return(loginModel, nil).Once()
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()

		checkResult, status, err := userManagement.CheckUserJWTToken("device-id-123")
		assert.NotEmpty(t, checkResult)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
		assert.Equal(t, "expired", checkResult["check_result"])
		t.Log(checkResult)
	})

	t.Run("inpire token", func(t *testing.T) {
		payload := map[string]interface{}{
			"sub":  1,
			"type": mock.Anything,
			"iat":  time.Now().UTC().Unix(),
			"eat":  time.Now().UTC().AddDate(0, 0, 2).Unix(),
		}

		mockRepository.Mock.On("FindOneLoginSession", umc, mock.Anything).Return(loginModel, nil).Once()
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()

		checkResult, status, err := userManagement.CheckUserJWTToken("device-id-123")
		assert.NotEmpty(t, checkResult)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
		assert.Equal(t, "ok", checkResult["check_result"])
		t.Log(checkResult)
	})
}

func TestUpdateUserJWTToken(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}
	umc := &configuration.UserManagement
	deviceModel := &contract.UserDeviceModel{
		ID:       1,
		DeviceID: mock.Anything,
		UserID:   1,
		UserType: mock.Anything,
	}

	t.Run("incomplete required data", func(t *testing.T) {
		token, status, err := userManagement.UpdateUserJWTToken(0, "")
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find user device", func(t *testing.T) {
		mockRepository.Mock.On("FindUserDevice", umc, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, errFoo).Once()

		token, status, err := userManagement.UpdateUserJWTToken(1, "device-id-123")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user device not exist", func(t *testing.T) {
		mockRepository.Mock.On("FindUserDevice", umc, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, nil).Once()

		token, status, err := userManagement.UpdateUserJWTToken(1, "device-id-123")
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("token signing failure", func(t *testing.T) {
		mockRepository.Mock.On("FindUserDevice", umc, mock.Anything, mock.Anything).Return(deviceModel, nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("", errFoo).Once()

		token, status, err := userManagement.UpdateUserJWTToken(1, "device-id-123")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update jwt token", func(t *testing.T) {
		mockRepository.Mock.On("FindUserDevice", umc, mock.Anything, mock.Anything).Return(deviceModel, nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return(mock.Anything, nil).Once()
		mockRepository.Mock.On("UpdateJWTToken", umc, mock.Anything, mock.Anything).Return(errFoo).Once()

		token, status, err := userManagement.UpdateUserJWTToken(1, "device-id-123")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mockRepository.Mock.On("FindUserDevice", umc, mock.Anything, mock.Anything).Return(deviceModel, nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return(mock.Anything, nil).Once()
		mockRepository.Mock.On("UpdateJWTToken", umc, mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.UpdateUserJWTToken(1, "device-id-123")
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestUpdateUserCredential(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}
	umc := &configuration.UserManagement
	user := &contract.UserModel{
		ID:           1,
		Username:     mock.Anything,
		Email:        mock.Anything,
		Password:     mock.Anything,
		PhotoProfile: mock.Anything,
		PhoneNumber:  mock.Anything,
	}

	t.Run("incomplete required data", func(t *testing.T) {
		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 0, "")
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("unmarked credential property", func(t *testing.T) {
		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 1, "domain")
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find one user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(&contract.UserModel{}, errFoo).Once()

		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 1, "username")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user not registered", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 1, "username")
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong current password", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(user, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(false).Once()

		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 1, "username")
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update credential", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(user, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockRepository.Mock.On("UpdateCredential", umc, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 1, "username")
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(user, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockRepository.Mock.On("UpdateCredential", umc, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		status, err := userManagement.UpdateUserCredential(mock.Anything, mock.Anything, 1, "username")
		assert.Equal(t, 200, status)
		assert.Empty(t, err)
	})
}

func TestUpdateUserPassword(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}
	umc := &configuration.UserManagement
	user := &contract.UserModel{
		ID:           1,
		Username:     mock.Anything,
		Email:        mock.Anything,
		Password:     mock.Anything,
		PhotoProfile: mock.Anything,
		PhoneNumber:  mock.Anything,
	}

	t.Run("incomplete required data", func(t *testing.T) {
		status, err := userManagement.UpdateUserPassword(mock.Anything, mock.Anything, 0)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find one user by id", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(&contract.UserModel{}, errFoo).Once()

		status, err := userManagement.UpdateUserPassword(mock.Anything, mock.Anything, 1)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("unregistered user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		status, err := userManagement.UpdateUserPassword(mock.Anything, mock.Anything, 1)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("wrong passwordr", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(user, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(false).Once()

		status, err := userManagement.UpdateUserPassword(mock.Anything, mock.Anything, 1)
		assert.Equal(t, 401, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error update password by user id", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(user, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockEncryption.Mock.On("Hash").Return(mock.Anything).Once()
		mockRepository.Mock.On("UpdateUserPasswordByUserID", umc, mock.Anything, mock.Anything).Return(errFoo).Once()

		status, err := userManagement.UpdateUserPassword(mock.Anything, mock.Anything, 1)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUserByID", umc, mock.Anything).Return(user, nil).Once()
		mockEncryption.Mock.On("Compare", mock.Anything, mock.Anything).Return(true).Once()
		mockEncryption.Mock.On("Hash").Return(mock.Anything).Once()
		mockRepository.Mock.On("UpdateUserPasswordByUserID", umc, mock.Anything, mock.Anything).Return(nil).Once()

		status, err := userManagement.UpdateUserPassword(mock.Anything, mock.Anything, 1)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

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
		_, err := UserManagement(&config, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
		assert.Empty(t, err)

		if err != nil {
			t.Fatal(err.Error())
		}
	})

	t.Run("incorrect user type", func(t *testing.T) {
		_, err := UserManagement(&config, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "User")
		assert.NotEmpty(t, err)
		if err != nil {
			t.Logf(err.Error())
		}
	})
}

func TestForgotPassword(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("empty credential", func(t *testing.T) {
		token, status, err := userManagement.ForgotPassword("")
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("invalid email", func(t *testing.T) {
		token, status, err := userManagement.ForgotPassword("godog@d87qwrgqwe.com")
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("invalid phone numbers", func(t *testing.T) {
		token, status, err := userManagement.ForgotPassword("08112123277")
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("solarislight@gmail.com")
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

	t.Run("error create RP token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
			PhoneNumber:  "08112123244",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate OTP", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
			PhoneNumber:  "08112123244",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error store password", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
			PhoneNumber:  "08112123244",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("OTP", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("safepw").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error proccess email template", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
			PhoneNumber:  "08112123244",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("OTP", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("safepw").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error send email", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
			PhoneNumber:  "08112123244",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("OTP", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("safepw").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("template", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success send email", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
			PhoneNumber:  "08112123244",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("OTP", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("safepw").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("template", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.ForgotPassword("dona@gmail.com")
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})

	t.Run("error send WA", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			PhoneNumber:  "08112123244",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("OTP", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("safepw").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockWhatsapp.Mock.On("SendMessage", mock.Anything, mock.Anything).Return(errFoo).Once()

		token, status, err := userManagement.ForgotPassword("+628112123255")
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success send WA", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "username",
			Email:        "dona@gmail.com",
			PhoneNumber:  "08112123244",
			Password:     "2345r4ea",
			PhotoProfile: "photo/a.jpg",
		}, nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("token", nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("OTP", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return("safepw").Once()
		mockRepository.Mock.On("StoreForgotPassword", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockWhatsapp.Mock.On("SendMessage", mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.ForgotPassword("+628112123255")
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestLogin(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("incomplete required data", func(t *testing.T) {
		user, token, status, err := userManagement.Login(mock.Anything, mock.Anything, "")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error sending security concern whatsapp invalid number", func(t *testing.T) {
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

		user, token, status, err := userManagement.Login("081121123266", mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error sending security concern whatsapp NOK", func(t *testing.T) {
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
		mockWhatsapp.Mock.On("SendMessage", mock.Anything, mock.Anything).Return(errFoo).Once()

		user, token, status, err := userManagement.Login("+6281121123266", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
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

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error complete login session", func(t *testing.T) {
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
		mockRepository.Mock.On("CompleteLoginSession", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success login", func(t *testing.T) {
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
		mockRepository.Mock.On("CompleteLoginSession", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		user, token, status, err := userManagement.Login("donadona@gmail.com", mock.Anything, "device-123")
		assert.NotEmpty(t, user)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestRegisterNewAccount(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("empty credential", func(t *testing.T) {
		token, status, err := userManagement.RegisterNewAccount("", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("empty device id", func(t *testing.T) {
		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", "", "fcm-token")
		assert.Empty(t, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("empty fcm id", func(t *testing.T) {
		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", "device-id", "")
		assert.Empty(t, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
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

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate OTP", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error check registration data", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration data found but error update registration", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{
			ID:                 1,
			Token:              mock.Anything,
			OTP:                mock.Anything,
			Credential:         mock.Anything,
			CreatedAt:          time.Now().Unix(),
			Type:               mock.Anything,
			RegistrationStatus: mock.Anything,
			DeviceID:           mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("UpdateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error create registration", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error proccess email template", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("template", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error send email", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("template", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success send email", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockTemplateProcessor.Mock.On("EmailTemplate", mock.Anything, mock.Anything).Return("template", nil).Once()
		mockMailer.Mock.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.RegisterNewAccount("dona@gmail.com", mock.Anything, mock.Anything)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestRegisterNewAccountWithPhoneNumber(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	phoneNumbers := "+628112123244"

	t.Run("error parse phone number", func(t *testing.T) {
		token, status, err := userManagement.RegisterNewAccount("08223", mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
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

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusUnauthorized, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate OTP", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error generate token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("", errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error check registration data", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration data found but error update registration", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{
			ID:                 1,
			Token:              mock.Anything,
			OTP:                mock.Anything,
			Credential:         mock.Anything,
			CreatedAt:          time.Now().Unix(),
			Type:               mock.Anything,
			RegistrationStatus: mock.Anything,
			DeviceID:           mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("UpdateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error create registration data", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("failed to send whatsapp", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockWhatsapp.Mock.On("SendMessage", mock.Anything, mock.Anything).Return(errors.New("intended error")).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.Empty(t, token)
		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("failed to send whatsapp", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockIdentifier.Mock.On("GenerateOTP").Return("123456", nil).Once()
		mockIdentifier.Mock.On("MakeIdentifier").Return("TOKEN", nil).Once()
		mockEncryption.Mock.On("Hash", mock.Anything).Return(mock.Anything).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()
		mockRepository.Mock.On("CreateRegistration", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockWhatsapp.Mock.On("SendMessage", mock.Anything, mock.Anything).Return(nil).Once()

		token, status, err := userManagement.RegisterNewAccount(phoneNumbers, mock.Anything, mock.Anything)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestRegisterNewAccountWithUncertainCredential(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("uncertain credential input", func(t *testing.T) {
		uncertainCredentials := []string{
			"duar",
			"081A",
			"gein@",
		}

		for _, v := range uncertainCredentials {
			t.Run(fmt.Sprintf("testing %s", v), func(t *testing.T) {
				token, status, err := userManagement.RegisterNewAccount("duar-teu-puguh", mock.Anything, mock.Anything)
				assert.Empty(t, token)
				assert.Equal(t, 400, status)
				assert.NotEmpty(t, err)
				t.Log(err.Error())
			})
		}
	})
}

func TestRegisterVerification(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("error find registration", func(t *testing.T) {
		status, err := userManagement.RegisterVerification("token", "")
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

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

func TestCompleteRegistration(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	DynamicColVal := contract.DynamicColumnValue{
		Column: "(username, email, phone, address)",
		Value:  []string{"user123", "user@gmail.com", "08112123244", "Jl. TB Depan No.79B"},
	}

	t.Run("incomplete required data", func(t *testing.T) {
		user, token, status, err := userManagement.CompleteRegistration("08112123244", nil)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("invalid email", func(t *testing.T) {
		user, token, status, err := userManagement.CompleteRegistration("guiltfree@doyoksuroyok.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("invalid phone numbers", func(t *testing.T) {
		user, token, status, err := userManagement.CompleteRegistration("08112123266", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error fond one user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("user already registered", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{ID: 1}, nil).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find registration by creditial", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("registration not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{}, nil).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("unverfied registration", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "unverified"}, nil).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error store user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(0, errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error store user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(0, errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error find stored user", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("stored user not found", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 404, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error create new user device", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error store fcm token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("StoreFCMToken", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error store fcm token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("StoreFCMToken", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error sign jwt token", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("StoreFCMToken", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("", errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("error create complete login session", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("StoreFCMToken", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("generatedtokendong", nil).Once()
		mockRepository.Mock.On("CreateCompleteLoginSession", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errFoo).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.Empty(t, user)
		assert.Empty(t, token)
		assert.Equal(t, 500, status)
		assert.NotEmpty(t, err)
		t.Log(err.Error())
	})

	t.Run("success operation", func(t *testing.T) {
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		mockRepository.Mock.On("FindOneRegistrationByCredential", &configuration.UserManagement, mock.Anything).Return(&contract.RegistrationModel{ID: 1, RegistrationStatus: "verified"}, nil).Once()
		mockRepository.Mock.On("StoreUser", &configuration.UserManagement, mock.Anything, mock.Anything).Return(1, nil).Once()
		mockRepository.Mock.On("FindOneUser", &configuration.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     mock.Anything,
			Email:        mock.Anything,
			PhotoProfile: mock.Anything,
			PhoneNumber:  mock.Anything,
		}, nil).Once()
		mockRepository.Mock.On("CreateNewUserDevice", &configuration.UserManagement, mock.Anything, mock.Anything).Return(nil).Once()
		mockRepository.Mock.On("StoreFCMToken", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockJWT.Mock.On("Sign", mock.Anything).Return("generatedtokendong", nil).Once()
		mockRepository.Mock.On("CreateCompleteLoginSession", &configuration.UserManagement, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		user, token, status, err := userManagement.CompleteRegistration("guiltfree@gmail.com", &DynamicColVal)
		assert.NotEmpty(t, user)
		assert.NotEmpty(t, token)
		assert.Equal(t, 200, status)
		assert.NoError(t, err)
	})
}

func TestResetPassword(t *testing.T) {
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
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
	userManagement, err := UserManagement(&configuration, &mockRepository, &mockIdentifier, &mockEncryption, &mockJWT, &mockMailer, &mockWhatsapp, &mockTemplateProcessor, "Admin")
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Run("empty device id", func(t *testing.T) {
		status, err := userManagement.Logout("")
		assert.Equal(t, 400, status)
		assert.NotEmpty(t, err)
		t.Logf("error : %v", err.Error())
	})

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
