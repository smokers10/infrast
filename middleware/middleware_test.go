package middleware

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
	errFoo     = errors.New("inteded error")
	userDevice = &contract.UserDeviceModel{
		ID:       1,
		DeviceID: mock.Anything,
		UserID:   1,
		UserType: mock.Anything,
	}
	login = &contract.LoginModel{
		ID:            1,
		Token:         mock.Anything,
		Credential:    mock.Anything,
		Type:          mock.Anything,
		DeviceID:      mock.Anything,
		LoginAt:       time.Now().UTC().Unix(),
		AttemptAt:     time.Now().UTC().Unix(),
		FailedCounter: 0,
	}
	user = &contract.UserModel{
		ID:           1,
		Username:     mock.Anything,
		Email:        mock.Anything,
		Password:     mock.Anything,
		PhotoProfile: mock.Anything,
		PhoneNumber:  mock.Anything,
	}
	payload = map[string]interface{}{
		"type":    "admin",
		"user_id": 10,
		"iat":     time.Now().UTC().Unix(),
		"eat":     time.Now().UTC().AddDate(0, 0, 7).Unix(),
	}
)

func TestAuthenticate(t *testing.T) {
	c := config.Configuration{
		Application: config.Application{
			Port:   ":8000",
			Secret: "this app test secret",
		},
		UserManagement: config.UserManagementConfig{
			Users: []config.User{
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
			},
			UserDevice: config.UserDeviceConfig{
				TableName:        "user_devices",
				IDProperty:       "id",
				DeviceIDProperty: "device_id",
				UserIDProperty:   "user_id",
				UserTypeProperty: "type",
			},
		},
	}
	// umc := c.UserManagement

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

	t.Run("token expired", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(map[string]interface{}{
			"type":    "admin",
			"user_id": 10,
			"iat":     time.Now().UTC().Unix(),
			"eat":     time.Now().UTC().AddDate(0, 0, -2).Unix(),
		}, nil).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("user type not match", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(map[string]interface{}{
			"type":    "robot go",
			"user_id": 10,
			"iat":     time.Now().Unix(),
			"eat":     time.Now().AddDate(0, 0, 7).Unix(),
		}, nil).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error fetch user device", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(&contract.UserDeviceModel{}, errFoo).Once()

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

	t.Run("error fetch login session", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(userDevice, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{}, errFoo).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("login session not found", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(userDevice, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(&contract.LoginModel{}, nil).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("error fetch user", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(userDevice, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(login, nil).Once()
		mockRepository.Mock.On("FindOneUser", &c.UserManagement, mock.Anything).Return(&contract.UserModel{}, errFoo).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("user not found", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(userDevice, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(login, nil).Once()
		mockRepository.Mock.On("FindOneUser", &c.UserManagement, mock.Anything).Return(&contract.UserModel{}, nil).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.Error(t, err)
		t.Logf("response : %v", res)
		t.Logf("err : %v", err)
	})

	t.Run("success authentication operation", func(t *testing.T) {
		mockJWT.Mock.On("ParseToken", mock.Anything).Return(payload, nil).Once()
		mockRepository.Mock.On("FindUserDevice", &c.UserManagement, mock.Anything, mock.Anything).Return(userDevice, nil).Once()
		mockRepository.Mock.On("FindOneLoginSession", &c.UserManagement, mock.Anything).Return(login, nil).Once()
		mockRepository.Mock.On("FindOneUser", &c.UserManagement, mock.Anything).Return(user, nil).Once()

		res, err := middleware.Authenticate("token", "device-id")
		assert.NoError(t, err)
		t.Logf("response : %v", res)
	})
}
