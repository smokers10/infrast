package middleware

import (
	"errors"
	"testing"
	"time"

	"github.com/smokers10/go-infrastructure/config"
	"github.com/smokers10/go-infrastructure/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthenticate(t *testing.T) {
	c := config.Configuration{
		Application: config.Application{
			Port:   ":8000",
			Secret: "this app test secret",
		},
		UserManagement: config.UserManagementConfig{
			UserCredential: []config.UserCredential{
				{
					Type:                 "admin",
					UserTable:            "admins",
					Credential:           []string{"email", "username"},
					IDProperty:           "id",
					PhotoProfileProperty: "photo_profile",
					PasswordProperty:     "password",
					UsernameProperty:     "username",
					EmailProperty:        "email",
					PhoneProperty:        "phone",
				},
				{
					Type:                 "user",
					UserTable:            "users",
					Credential:           []string{"email", "username"},
					IDProperty:           "id",
					PhotoProfileProperty: "photo_profile",
					PasswordProperty:     "password",
					UsernameProperty:     "username",
					EmailProperty:        "email",
					PhoneProperty:        "phone",
				},
			},
			Login: config.LoginConfig{
				TableName:             "login",
				TokenProperty:         "token",
				FailedCounterProperty: "failed_attempt",
				TypeProperty:          "type",
				CredentialProperty:    "credential",
				LoginAtProperty:       "loged_at",
				DeviceIDProperty:      "device_id",
				MaxFailedAttempt:      3,
				LoginBlockDuration:    300,
				AttemptAtProperty:     "attemped_at",
				EmailTemplatePath:     "template-email/login-secuity-concern.html",
			},
			UserDevice: config.UserDeviceConfig{
				TableName:         "user_devices",
				IDProperty:        "id",
				DeviceIDProperty:  "device_id",
				UserIDProperty:    "user_id",
				UserTypeProperty:  "type",
				EmailTemplatePath: "template-email/login-secuirty-concern.html",
			},
		},
	}
	payload := map[string]interface{}{
		"type":    "admin",
		"user_id": 10,
		"iat":     time.Now().AddDate(0, 0, 7).Unix(),
	}

	mockRepository := contract.UserManagementRepositoryMock{Mock: mock.Mock{}}
	mockJWT := contract.JsonWebTokenContractMock{Mock: mock.Mock{}}

	// define middleware
	middleware, err := Middleware(&c.UserManagement, &mockRepository, &mockJWT, "admin")
	if err != nil {
		t.Logf(err.Error())
	}

	t.Run("empty param", func(t *testing.T) {
		res, err := middleware.Authenticate("", "")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error parsing token", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(map[string]interface{}{}, errors.New("intended error")).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("user type not match", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(map[string]interface{}{
			"type":    "robot go",
			"user_id": 10,
			"iat":     time.Now().AddDate(0, 0, 7).Unix(),
		}, nil).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error get user device", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, errors.New("inteded error")).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("user device not found", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, nil).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error get login session", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: "device-id",
			UserID:   1,
			UserType: "admin",
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{}, errors.New("intended error")).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("loggin session not found", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: "device-id",
			UserID:   1,
			UserType: "admin",
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{}, nil).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error get user data", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: "device-id",
			UserID:   1,
			UserType: "admin",
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{
			ID:            1,
			Token:         "token",
			Credential:    "user@gmail.com",
			Type:          "admin",
			DeviceID:      "device-id",
			LoginAt:       time.Now().Unix(),
			AttemptAt:     time.Now().Unix(),
			FailedCounter: 1,
		}, nil).Once()
		mockRepository.Mock.On("FindOneUser", &c.UserManagement, mock.Anything).Return(&contract.UserModel{}, errors.New("inteded error")).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error get user data", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: "device-id",
			UserID:   1,
			UserType: "admin",
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{
			ID:            1,
			Token:         "token",
			Credential:    "user@gmail.com",
			Type:          "admin",
			DeviceID:      "device-id",
			LoginAt:       time.Now().Unix(),
			AttemptAt:     time.Now().Unix(),
			FailedCounter: 1,
		}, nil).Once()
		mockRepository.Mock.On("FindOneUser", &c.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("success authentication operation", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{
			ID:       1,
			DeviceID: "device-id",
			UserID:   1,
			UserType: "admin",
		}, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{
			ID:            1,
			Token:         "token",
			Credential:    "user@gmail.com",
			Type:          "admin",
			DeviceID:      "device-id",
			LoginAt:       time.Now().Unix(),
			AttemptAt:     time.Now().Unix(),
			FailedCounter: 1,
		}, nil).Once()
		mockRepository.Mock.On("FindOneUser", &c.UserManagement, mock.Anything).Return(&contract.UserModel{
			ID:           1,
			Username:     "user1",
			Email:        "user1@gmail.com",
			Password:     "aspidua98shas",
			PhotoProfile: "pp/a.jpg",
			PhoneNumber:  "081121213244",
		}, nil).Once()
		res, err := middleware.Authenticate("token", "device-id")
		assert.NoError(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})
}
